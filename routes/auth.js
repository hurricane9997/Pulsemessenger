const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const logger = require('../lib/logger');
const memStore = require('../lib/memStore');
const { sendVerificationOtp, sendResetOtp, sendWelcomeEmail, sendSMS } = require('../lib/notifications');
const { validateRegister, validateLogin, validateOtp, validatePassword } = require('../middleware/validate');

// Lazy-load User model
const getUser = () => {
  try { return require('../models/User'); } catch { return null; }
};

// ─── Rate Limiters ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again in 15 minutes.' } });
const otpLimiter  = rateLimit({ windowMs: 5 * 60 * 1000,  max: 5,  message: { error: 'Too many OTP attempts.' } });
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many reset attempts.' } });

// ─── Helpers ──────────────────────────────────────────────────────────────────
const genOtp = () => crypto.randomInt(100000, 999999).toString();
const otpExpiry = () => new Date(Date.now() + (parseInt(process.env.OTP_EXPIRY_MINS) || 10) * 60 * 1000);
const hashOtp = (otp) => crypto.createHash('sha256').update(otp).digest('hex');

// Use memory or mongo
const db = {
  async findByEmail(email) {
    if (memStore.isActive()) return memStore.findByEmail(email);
    const User = getUser();
    return User ? User.findOne({ email }).select('+password +emailOtp +emailOtpExpiry +phoneOtp +phoneOtpExpiry +resetToken +resetTokenExpiry +resetPhoneOtp +resetPhoneOtpExpiry') : null;
  },
  async create(data) {
    if (memStore.isActive()) return memStore.create(data);
    const User = getUser();
    return User ? User.create(data) : null;
  },
  async findByResetToken(token) {
    if (memStore.isActive()) return memStore.findByResetToken(token);
    const User = getUser();
    return User ? User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } }).select('+resetToken +resetTokenExpiry +resetPhoneOtp +resetPhoneOtpExpiry') : null;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/register  — Step 1: create account + send email OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post('/register', authLimiter, validateRegister, async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    // Check duplicate
    const existing = await db.findByEmail(email);
    if (existing) {
      // Timing-safe: same delay regardless
      await new Promise(r => setTimeout(r, 300));
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const otp = genOtp();
    const user = await db.create({
      fullName, email, phone, password,
      emailOtp: hashOtp(otp),
      emailOtpExpiry: otpExpiry(),
    });

    await sendVerificationOtp(email, otp);

    // Log OTP in dev
    if (!process.env.EMAIL_USER) logger.debug(`[DEV] Email OTP for ${email}: ${otp}`);

    req.session.regEmail = email;

    res.json({ success: true, step: 'verify-email', message: `Verification code sent to ${email}` });
  } catch (err) {
    logger.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-email  — Step 2: confirm email OTP → send phone OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-email', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.regEmail;
    if (!email) return res.status(400).json({ error: 'Session expired. Please register again.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    if (!user.emailOtpExpiry || user.emailOtpExpiry < Date.now())
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });

    if (user.emailOtp !== hashOtp(req.body.otp))
      return res.status(400).json({ error: 'Invalid OTP. Please try again.' });

    // Mark email verified
    user.emailVerified = true;
    user.emailOtp = undefined;
    user.emailOtpExpiry = undefined;

    // Send phone OTP
    const otp = genOtp();
    user.phoneOtp = hashOtp(otp);
    user.phoneOtpExpiry = otpExpiry();
    await user.save();

    await sendSMS(user.phone, `Your SecureAuth verification code: ${otp}. Expires in ${process.env.OTP_EXPIRY_MINS || 10} mins.`);
    if (!process.env.TWILIO_ACCOUNT_SID) logger.debug(`[DEV] Phone OTP for ${user.phone}: ${otp}`);

    res.json({ success: true, step: 'verify-phone', message: `Code sent to ${maskPhone(user.phone)}` });
  } catch (err) {
    logger.error('Verify email error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-phone  — Step 3: confirm phone OTP → activate account
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-phone', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.regEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    if (!user.phoneOtpExpiry || user.phoneOtpExpiry < Date.now())
      return res.status(400).json({ error: 'OTP has expired.' });

    if (user.phoneOtp !== hashOtp(req.body.otp))
      return res.status(400).json({ error: 'Invalid OTP.' });

    user.phoneVerified = true;
    user.isActive = true;
    user.phoneOtp = undefined;
    user.phoneOtpExpiry = undefined;
    await user.save();

    delete req.session.regEmail;

    await sendWelcomeEmail(email, user.fullName);

    res.json({ success: true, step: 'complete', message: 'Account verified and activated! You can now log in.' });
  } catch (err) {
    logger.error('Verify phone error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.findByEmail(email);

    // Timing-safe rejection
    if (!user) {
      await new Promise(r => setTimeout(r, 300));
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.isLocked) {
      const mins = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${mins} minute(s).` });
    }

    if (!user.isActive)
      return res.status(403).json({ error: 'Account not verified. Please complete registration.' });

    const match = await user.comparePassword(password);
    if (!match) {
      await user.incLoginAttempts();
      const remaining = Math.max(0, (parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5) - user.loginAttempts);
      return res.status(401).json({ error: `Invalid email or password. ${remaining > 0 ? `${remaining} attempt(s) remaining.` : 'Account locked.'}` });
    }

    await user.resetLoginAttempts();
    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    await user.save();

    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Login failed.' });
      req.session.userId = user._id || user.email;
      req.session.userEmail = user.email;
      req.session.userName = user.fullName;
      res.json({
        success: true,
        user: { name: user.fullName, email: user.email, lastLogin: user.lastLogin },
      });
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot-password — send email OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post('/forgot-password', resetLimiter, async (req, res) => {
  try {
    const email = req.body.email;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    // Always return success to prevent user enumeration
    const user = await db.findByEmail(email);

    if (user && user.isActive) {
      const otp = genOtp();
      user.resetToken = crypto.randomBytes(32).toString('hex');
      user.resetTokenExpiry = otpExpiry();
      user.emailOtp = hashOtp(otp);
      user.emailOtpExpiry = otpExpiry();
      await user.save();

      await sendResetOtp(email, otp);
      if (!process.env.EMAIL_USER) logger.debug(`[DEV] Reset OTP for ${email}: ${otp}`);

      req.session.resetEmail = email;
      req.session.resetToken = user.resetToken;
    }

    res.json({ success: true, message: 'If an account exists with this email, a reset code has been sent.' });
  } catch (err) {
    logger.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-reset-email — verify email OTP for reset
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-reset-email', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.resetEmail;
    if (!email) return res.status(400).json({ error: 'Session expired. Start over.' });

    const user = await db.findByEmail(email);
    if (!user || !user.emailOtpExpiry || user.emailOtpExpiry < Date.now())
      return res.status(400).json({ error: 'OTP expired or invalid.' });

    if (user.emailOtp !== hashOtp(req.body.otp))
      return res.status(400).json({ error: 'Invalid OTP.' });

    user.emailOtp = undefined;
    user.emailOtpExpiry = undefined;

    // Now send phone OTP
    const otp = genOtp();
    user.resetPhoneOtp = hashOtp(otp);
    user.resetPhoneOtpExpiry = otpExpiry();
    await user.save();

    await sendSMS(user.phone, `SecureAuth password reset code: ${otp}. Expires in ${process.env.OTP_EXPIRY_MINS || 10} mins.`);
    if (!process.env.TWILIO_ACCOUNT_SID) logger.debug(`[DEV] Reset Phone OTP: ${otp}`);

    res.json({ success: true, step: 'verify-reset-phone', message: `Code sent to ${maskPhone(user.phone)}` });
  } catch (err) {
    logger.error('Verify reset email error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-reset-phone — verify phone OTP for reset
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-reset-phone', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.resetEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user || !user.resetPhoneOtpExpiry || user.resetPhoneOtpExpiry < Date.now())
      return res.status(400).json({ error: 'OTP expired.' });

    if (user.resetPhoneOtp !== hashOtp(req.body.otp))
      return res.status(400).json({ error: 'Invalid OTP.' });

    user.resetPhoneOtp = undefined;
    user.resetPhoneOtpExpiry = undefined;
    await user.save();

    req.session.resetVerified = true;

    res.json({ success: true, step: 'new-password', message: 'Identity verified. Set your new password.' });
  } catch (err) {
    logger.error('Verify reset phone error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/reset-password — set new password
// ─────────────────────────────────────────────────────────────────────────────
router.post('/reset-password', resetLimiter, validatePassword, async (req, res) => {
  try {
    if (!req.session.resetVerified || !req.session.resetEmail)
      return res.status(403).json({ error: 'Unauthorized. Complete verification first.' });

    const user = await db.findByEmail(req.session.resetEmail);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    user.password = req.body.password;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    // Destroy session
    req.session.destroy();

    res.json({ success: true, message: 'Password reset successfully. Please log in.' });
  } catch (err) {
    logger.error('Reset password error:', err);
    res.status(500).json({ error: 'Password reset failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/resend-otp — resend OTP
// ─────────────────────────────────────────────────────────────────────────────
router.post('/resend-otp', otpLimiter, async (req, res) => {
  try {
    const { type } = req.body; // 'email-reg', 'phone-reg', 'email-reset', 'phone-reset'
    const email = req.session.regEmail || req.session.resetEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    const otp = genOtp();

    if (type === 'email-reg' || type === 'email-reset') {
      user.emailOtp = hashOtp(otp);
      user.emailOtpExpiry = otpExpiry();
      await user.save();
      await (type === 'email-reset' ? sendResetOtp(email, otp) : sendVerificationOtp(email, otp));
      if (!process.env.EMAIL_USER) logger.debug(`[DEV] Resent email OTP: ${otp}`);
    } else {
      user.phoneOtp = hashOtp(otp);
      user.phoneOtpExpiry = otpExpiry();
      await user.save();
      await sendSMS(user.phone, `Your SecureAuth code: ${otp}`);
      if (!process.env.TWILIO_ACCOUNT_SID) logger.debug(`[DEV] Resent phone OTP: ${otp}`);
    }

    res.json({ success: true, message: 'New code sent.' });
  } catch (err) {
    logger.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Failed to resend code.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('__Host-sid');
    res.json({ success: true, message: 'Logged out.' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/me — check session
// ─────────────────────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: { name: req.session.userName, email: req.session.userEmail } });
});

// ─── Utils ────────────────────────────────────────────────────────────────────
const maskPhone = (phone) => {
  if (!phone || phone.length < 4) return '***';
  return phone.slice(0, -4).replace(/\d/g, '*') + phone.slice(-4);
};

module.exports = router;
