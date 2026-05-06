'use strict';

const express    = require('express');
const router     = express.Router();
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const logger     = require('../lib/logger');
const memStore   = require('../lib/memStore');
const sms        = require('../lib/sms');
const { sendVerificationOtp, sendResetOtp, sendWelcomeEmail } = require('../lib/notifications');
const { validateRegister, validateLogin, validateOtp, validatePassword } = require('../middleware/validate');

const getUser = () => { try { return require('../models/User'); } catch { return null; } };

const authLimiter    = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts, try again in 15 minutes.' } });
const otpLimiter     = rateLimit({ windowMs:  5*60*1000, max: 10, message: { error: 'Too many OTP attempts.' } });
const resetLimiter   = rateLimit({ windowMs: 60*60*1000, max:  5, message: { error: 'Too many reset attempts.' } });
const smsTestLimiter = rateLimit({ windowMs: 60*60*1000, max:  5, message: { error: 'Too many test requests.' } });

const db = {
  async findByEmail(email) {
    if (memStore.isActive()) return memStore.findByEmail(email);
    const U = getUser();
    return U ? U.findOne({ email }).select('+password +emailOtp +emailOtpExpiry +phoneOtp +phoneOtpExpiry +resetToken +resetTokenExpiry +resetPhoneOtp +resetPhoneOtpExpiry') : null;
  },
  async create(data) {
    if (memStore.isActive()) return memStore.create(data);
    const U = getUser();
    return U ? U.create(data) : null;
  },
};

const genOtp    = () => crypto.randomInt(100000, 999999).toString();
const otpExpiry = () => new Date(Date.now() + (parseInt(process.env.OTP_EXPIRY_MINS) || 10) * 60 * 1000);
const hashOtp   = (otp) => crypto.createHash('sha256').update(otp).digest('hex');
const maskPhone = (p) => { if (!p || p.length < 4) return '***'; return p.slice(0,-4).replace(/\d/g,'*') + p.slice(-4); };

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/sms-status
// ─────────────────────────────────────────────────────────────────────────────
router.get('/sms-status', (req, res) => {
  const s = sms.getProviderStatus();
  res.json({
    providers: {
      twilio:       s.twilio       ? '✓ configured' : '✗ not set',
      fast2sms:     s.fast2sms     ? '✓ configured' : '✗ not set',
      textbelt:     s.textbelt     ? '✓ configured' : '✗ not set',
      emailGateway: s.emailGateway ? '✓ configured' : '✗ not set',
    },
    anyActive: s.anyConfigured,
    mode:      s.anyConfigured ? 'live' : 'dev-console',
    carriers:  Object.keys(sms.CARRIER_GATEWAYS),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/sms-test  (requires X-Admin-Token in production)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/sms-test', smsTestLimiter, async (req, res) => {
  const isAdmin = req.headers['x-admin-token'] && req.headers['x-admin-token'] === process.env.ADMIN_TOKEN;
  if (process.env.NODE_ENV === 'production' && !isAdmin)
    return res.status(403).json({ error: 'Requires X-Admin-Token header in production.' });

  const { phone, carrier } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone is required.' });

  const origCarrier = process.env.SMS_CARRIER;
  if (carrier) process.env.SMS_CARRIER = carrier;

  try {
    const result = await sms.sendOtp(phone, 'test');
    if (carrier) process.env.SMS_CARRIER = origCarrier;
    res.json({
      success:   true,
      provider:  result.provider,
      message:   `OTP sent via ${result.provider}. Check your phone.`,
      expiresAt: new Date(result.expiresAt).toISOString(),
      note:      result.provider === 'dev-console' ? 'No SMS provider configured — OTP in server logs.' : undefined,
    });
  } catch (err) {
    if (carrier) process.env.SMS_CARRIER = origCarrier;
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/register
// ─────────────────────────────────────────────────────────────────────────────
router.post('/register', authLimiter, validateRegister, async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    const existing = await db.findByEmail(email);
    if (existing) {
      await new Promise(r => setTimeout(r, 300));
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const otp = genOtp();
    await db.create({ fullName, email, phone, password, emailOtp: hashOtp(otp), emailOtpExpiry: otpExpiry() });

    await sendVerificationOtp(email, otp);
    req.session.regEmail = email;

    res.json({ success: true, step: 'verify-email', message: `Verification code sent to ${email}` });
  } catch (err) {
    logger.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-email  →  sends SMS via new engine
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-email', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.regEmail;
    if (!email) return res.status(400).json({ error: 'Session expired. Please register again.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    if (!user.emailOtpExpiry || user.emailOtpExpiry < Date.now())
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });

    if (user.emailOtp !== hashOtp(req.body.otp))
      return res.status(400).json({ error: 'Invalid OTP. Please try again.' });

    user.emailVerified  = true;
    user.emailOtp       = undefined;
    user.emailOtpExpiry = undefined;
    await user.save();

    let provider = 'pending';
    try {
      const result = await sms.sendOtp(user.phone, 'verify');
      req.session.smsPhone    = user.phone;
      req.session.smsProvider = result.provider;
      provider = result.provider;
    } catch (smsErr) {
      logger.warn('SMS send failed (user can resend):', smsErr.message);
    }

    res.json({ success: true, step: 'verify-phone', message: `Code sent to ${maskPhone(user.phone)}`, provider });
  } catch (err) {
    logger.error('Verify email error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-phone  →  verifies via SMS engine
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-phone', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.regEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    try {
      sms.verifyOtp(user.phone, 'verify', req.body.otp);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    user.phoneVerified  = true;
    user.isActive       = true;
    user.phoneOtp       = undefined;
    user.phoneOtpExpiry = undefined;
    await user.save();

    delete req.session.regEmail;
    delete req.session.smsPhone;

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
      const rem = Math.max(0, (parseInt(process.env.MAX_LOGIN_ATTEMPTS)||5) - user.loginAttempts);
      return res.status(401).json({ error: `Invalid email or password. ${rem > 0 ? rem+' attempt(s) remaining.' : 'Account locked.'}` });
    }

    await user.resetLoginAttempts();
    user.lastLogin   = new Date();
    user.lastLoginIp = req.ip;
    await user.save();

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Login failed.' });
      req.session.userId    = user._id || user.email;
      req.session.userEmail = user.email;
      req.session.userName  = user.fullName;
      res.json({ success: true, user: { name: user.fullName, email: user.email, lastLogin: user.lastLogin } });
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot-password
// ─────────────────────────────────────────────────────────────────────────────
router.post('/forgot-password', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await db.findByEmail(email);
    if (user && user.isActive) {
      const otp = genOtp();
      user.resetToken       = crypto.randomBytes(32).toString('hex');
      user.resetTokenExpiry = otpExpiry();
      user.emailOtp         = hashOtp(otp);
      user.emailOtpExpiry   = otpExpiry();
      await user.save();
      await sendResetOtp(email, otp);
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
// POST /api/auth/verify-reset-email  →  sends SMS via engine
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

    user.emailOtp       = undefined;
    user.emailOtpExpiry = undefined;
    await user.save();

    let provider = 'pending';
    try {
      const result = await sms.sendOtp(user.phone, 'reset');
      req.session.resetSmsPhone    = user.phone;
      req.session.resetSmsProvider = result.provider;
      provider = result.provider;
    } catch (smsErr) {
      logger.warn('Reset SMS failed:', smsErr.message);
    }

    res.json({ success: true, step: 'verify-reset-phone', message: `Code sent to ${maskPhone(user.phone)}`, provider });
  } catch (err) {
    logger.error('Verify reset email error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/verify-reset-phone
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify-reset-phone', otpLimiter, validateOtp, async (req, res) => {
  try {
    const email = req.session.resetEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    try {
      sms.verifyOtp(user.phone, 'reset', req.body.otp);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    user.resetPhoneOtp       = undefined;
    user.resetPhoneOtpExpiry = undefined;
    await user.save();

    req.session.resetVerified = true;
    delete req.session.resetSmsPhone;

    res.json({ success: true, step: 'new-password', message: 'Identity verified. Set your new password.' });
  } catch (err) {
    logger.error('Verify reset phone error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/reset-password
// ─────────────────────────────────────────────────────────────────────────────
router.post('/reset-password', resetLimiter, validatePassword, async (req, res) => {
  try {
    if (!req.session.resetVerified || !req.session.resetEmail)
      return res.status(403).json({ error: 'Unauthorized. Complete verification first.' });

    const user = await db.findByEmail(req.session.resetEmail);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    user.password         = req.body.password;
    user.resetToken       = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    req.session.destroy();
    res.json({ success: true, message: 'Password reset successfully. Please log in.' });
  } catch (err) {
    logger.error('Reset password error:', err);
    res.status(500).json({ error: 'Password reset failed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/resend-otp
// ─────────────────────────────────────────────────────────────────────────────
router.post('/resend-otp', otpLimiter, async (req, res) => {
  try {
    const { type } = req.body;
    const email = req.session.regEmail || req.session.resetEmail;
    if (!email) return res.status(400).json({ error: 'Session expired.' });

    const user = await db.findByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    if (type === 'email-reg' || type === 'email-reset') {
      const otp = genOtp();
      user.emailOtp       = hashOtp(otp);
      user.emailOtpExpiry = otpExpiry();
      await user.save();
      await (type === 'email-reset' ? sendResetOtp(email, otp) : sendVerificationOtp(email, otp));
      return res.json({ success: true, message: 'New email code sent.' });
    }

    const purpose = type === 'phone-reset' ? 'reset' : 'verify';
    try {
      const result = await sms.sendOtp(user.phone, purpose);
      res.json({ success: true, message: `New code sent via ${result.provider}.`, provider: result.provider });
    } catch (smsErr) {
      if (smsErr.code === 'RATE_LIMIT')
        return res.status(429).json({ error: smsErr.message });
      throw smsErr;
    }
  } catch (err) {
    logger.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Failed to resend code.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ success: true, message: 'Logged out.' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/me
// ─────────────────────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: { name: req.session.userName, email: req.session.userEmail } });
});

module.exports = router;
