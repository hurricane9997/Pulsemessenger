/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║          SecureAuth — Self-Hosted SMS Authenticator          ║
 * ║  Multi-provider OTP delivery with automatic failover         ║
 * ║                                                              ║
 * ║  Delivery chain (tries each until one succeeds):            ║
 * ║   1. Twilio          (if TWILIO_* vars set)                 ║
 * ║   2. Fast2SMS        (India, free tier — FAST2SMS_KEY)       ║
 * ║   3. TextBelt        (TEXTBELT_KEY or 'textbelt' free tier)  ║
 * ║   4. Email-to-SMS    (carrier gateway — no extra account)    ║
 * ║   5. Dev fallback    (log to console — never in production)  ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const logger = require('./logger');

// ─── In-memory OTP store (replaced by DB when MongoDB is configured) ──────────
const otpStore = new Map();   // key → { hash, expiry, attempts, phone, purpose }
const rateStore = new Map();  // phone → [timestamps]

// ─── Constants ────────────────────────────────────────────────────────────────
const OTP_EXPIRY_MS  = (parseInt(process.env.OTP_EXPIRY_MINS)  || 10) * 60 * 1000;
const OTP_MAX_TRIES  = 5;
const OTP_RATE_LIMIT = 3;                  // max sends per window
const OTP_RATE_WIN   = 10 * 60 * 1000;    // 10-minute window

// ─── Helpers ──────────────────────────────────────────────────────────────────
const hashOtp   = (otp)  => crypto.createHash('sha256').update(otp + process.env.SESSION_SECRET).digest('hex');
const genOtp    = ()     => crypto.randomInt(100000, 999999).toString();
const genKey    = (phone, purpose) => `${purpose}:${crypto.createHash('sha256').update(phone).digest('hex').slice(0,16)}`;

/** Normalise phone to E.164 (+CountryCode...) */
const normalise = (phone) => {
  let p = String(phone).replace(/[\s\-().]/g, '');
  if (!p.startsWith('+')) p = '+' + p;
  return p;
};

/** Simple HTTP/S POST helper (no extra deps beyond axios which we added) */
const post = (url, data, headers = {}) => {
  return new Promise((resolve, reject) => {
    const axios = require('axios');
    axios.post(url, data, { headers, timeout: 8000 })
      .then(r  => resolve({ ok: r.status >= 200 && r.status < 300, status: r.status, body: r.data }))
      .catch(e => reject(e));
  });
};

const get = (url, headers = {}) => {
  return new Promise((resolve, reject) => {
    const axios = require('axios');
    axios.get(url, { headers, timeout: 8000 })
      .then(r  => resolve({ ok: r.status >= 200 && r.status < 300, status: r.status, body: r.data }))
      .catch(e => reject(e));
  });
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROVIDER 1 — Twilio (international, paid, most reliable)
// Env: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE
// ═══════════════════════════════════════════════════════════════════════════════
const sendViaTwilio = async (phone, message) => {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) return null;

  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_PHONE;
  const auth  = Buffer.from(`${sid}:${token}`).toString('base64');

  const params = new URLSearchParams({ To: phone, From: from, Body: message });

  const result = await post(
    `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`,
    params.toString(),
    {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    }
  );

  if (result.ok && result.body && !result.body.error_code) {
    logger.info(`[SMS] Twilio → ${phone} ✓ (SID: ${result.body.sid})`);
    return { provider: 'twilio', sid: result.body.sid };
  }
  throw new Error(`Twilio error: ${JSON.stringify(result.body)}`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROVIDER 2 — Fast2SMS (India, free tier available)
// Env: FAST2SMS_KEY
// ═══════════════════════════════════════════════════════════════════════════════
const sendViaFast2SMS = async (phone, message) => {
  if (!process.env.FAST2SMS_KEY) return null;

  // Strip country code for Fast2SMS (accepts 10-digit Indian numbers)
  const num = phone.replace(/^\+91/, '').replace(/\D/g, '');
  if (num.length !== 10) return null;

  const result = await post(
    'https://www.fast2sms.com/dev/bulkV2',
    null,
    {
      'authorization': process.env.FAST2SMS_KEY,
      'Content-Type': 'application/json',
    }
  );

  // Use GET API which Fast2SMS supports
  const url = `https://www.fast2sms.com/dev/bulkV2?authorization=${process.env.FAST2SMS_KEY}&sender_id=FSTSMS&message=${encodeURIComponent(message)}&language=english&route=p&numbers=${num}`;
  const res = await get(url, { 'authorization': process.env.FAST2SMS_KEY });

  if (res.ok && res.body && res.body.return === true) {
    logger.info(`[SMS] Fast2SMS → ${phone} ✓`);
    return { provider: 'fast2sms' };
  }
  throw new Error(`Fast2SMS error: ${JSON.stringify(res.body)}`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROVIDER 3 — TextBelt (simple REST SMS, free 1/day or paid)
// Env: TEXTBELT_KEY (use 'textbelt' for 1 free SMS/day per IP)
// ═══════════════════════════════════════════════════════════════════════════════
const sendViaTextBelt = async (phone, message) => {
  const key = process.env.TEXTBELT_KEY;
  if (!key) return null;

  const params = new URLSearchParams({ phone, message, key });
  const result = await post(
    'https://textbelt.com/text',
    params.toString(),
    { 'Content-Type': 'application/x-www-form-urlencoded' }
  );

  if (result.ok && result.body && result.body.success === true) {
    logger.info(`[SMS] TextBelt → ${phone} ✓ (remaining: ${result.body.quotaRemaining})`);
    return { provider: 'textbelt', remaining: result.body.quotaRemaining };
  }
  throw new Error(`TextBelt error: ${JSON.stringify(result.body)}`);
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROVIDER 4 — Email-to-SMS Gateway (FREE — uses carrier email gateways)
// No extra account needed — just needs EMAIL_USER configured
// Supports: AT&T, Verizon, T-Mobile, Sprint, Vodafone, Airtel, Jio, and more
// ═══════════════════════════════════════════════════════════════════════════════
const CARRIER_GATEWAYS = {
  // USA
  'att':       '@txt.att.net',
  'verizon':   '@vtext.com',
  'tmobile':   '@tmomail.net',
  'sprint':    '@messaging.sprintpcs.com',
  'boost':     '@sms.myboostmobile.com',
  'cricket':   '@sms.cricketwireless.net',
  'metro':     '@mymetropcs.com',
  'uscellular':'@email.uscc.net',
  // India
  'airtel':    '@airtelap.com',
  'jio':       '@jiomail.com',           // unofficial — may not work
  'vi':        '@vimail.in',
  'bsnl':      '@sms.bsnl.in',
  // UK
  'vodafone':  '@vodafone.net',
  'o2':        '@o2imail.co.uk',
  'ee':        '@mms.ee.co.uk',
  // Canada
  'rogers':    '@pcs.rogers.com',
  'bell':      '@txt.bell.ca',
  'telus':     '@msg.telus.com',
  // Australia
  'optus':     '@optusmobile.com.au',
  'telstra':   '@sms.telstra.com',
};

const sendViaEmailGateway = async (phone, message, carrier) => {
  if (!process.env.EMAIL_USER) return null;

  const gateway = carrier
    ? CARRIER_GATEWAYS[carrier.toLowerCase()]
    : process.env.SMS_GATEWAY;           // e.g. "@txt.att.net"

  if (!gateway) return null;

  const num = phone.replace(/\D/g, '').slice(-10); // last 10 digits
  const smsEmail = `${num}${gateway}`;

  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: false,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls:  { rejectUnauthorized: true },
  });

  await transporter.sendMail({
    from:    process.env.EMAIL_USER,
    to:      smsEmail,
    subject: '',
    text:    message,   // plain text only for SMS gateways
  });

  logger.info(`[SMS] Email-gateway (${gateway}) → ${smsEmail} ✓`);
  return { provider: 'email-gateway', gateway };
};

// ═══════════════════════════════════════════════════════════════════════════════
// RATE LIMITER — prevents SMS flooding/abuse
// ═══════════════════════════════════════════════════════════════════════════════
const checkRateLimit = (phone) => {
  const now  = Date.now();
  const key  = `rl:${phone}`;
  const times = (rateStore.get(key) || []).filter(t => now - t < OTP_RATE_WIN);

  if (times.length >= OTP_RATE_LIMIT) {
    const waitSecs = Math.ceil((times[0] + OTP_RATE_WIN - now) / 1000);
    throw Object.assign(new Error(`Too many OTP requests. Wait ${waitSecs}s.`), { code: 'RATE_LIMIT', waitSecs });
  }

  times.push(now);
  rateStore.set(key, times);
};

// ─── Cleanup stale rate entries every 30 min ─────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateStore.entries()) {
    if (v.every(t => now - t > OTP_RATE_WIN)) rateStore.delete(k);
  }
}, 30 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN: sendOtp(phone, purpose) → { key, expiresAt }
// ═══════════════════════════════════════════════════════════════════════════════
const sendOtp = async (phone, purpose = 'verify') => {
  phone = normalise(phone);
  checkRateLimit(phone);   // throws if rate limited

  const otp       = genOtp();
  const key       = genKey(phone, purpose);
  const expiresAt = Date.now() + OTP_EXPIRY_MS;

  // Store hashed OTP
  otpStore.set(key, {
    hash:      hashOtp(otp),
    expiresAt,
    attempts:  0,
    phone,
    purpose,
    createdAt: Date.now(),
  });

  const message = buildMessage(otp, purpose);

  // ── Try providers in order ───────────────────────────────────────────────
  const providers = [
    () => sendViaTwilio(phone, message),
    () => sendViaFast2SMS(phone, message),
    () => sendViaTextBelt(phone, message),
    () => sendViaEmailGateway(phone, message, process.env.SMS_CARRIER),
  ];

  let lastError = null;
  for (const provider of providers) {
    try {
      const result = await provider();
      if (result) {
        logger.info(`[SMS] OTP delivered via ${result.provider} to ${maskPhone(phone)}`);
        return { key, expiresAt, provider: result.provider };
      }
    } catch (err) {
      logger.warn(`[SMS] Provider failed: ${err.message}`);
      lastError = err;
    }
  }

  // ── Dev fallback ─────────────────────────────────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    logger.debug(`[DEV] Phone OTP for ${phone}: ${otp}`);
    logger.warn(`[DEV] SMS to ${phone}: ${message}`);
    return { key, expiresAt, provider: 'dev-console' };
  }

  // In production with no provider configured — still log to Railway logs
  // so admin can relay it manually during setup
  logger.warn(`[SETUP] No SMS provider configured. OTP for ${maskPhone(phone)}: [check secure logs]`);
  logger.debug(`[SETUP-OTP] ${phone}: ${otp}`);   // Only visible at debug level

  throw new Error(lastError
    ? `SMS delivery failed: ${lastError.message}`
    : 'No SMS provider configured. Set TWILIO_*, FAST2SMS_KEY, TEXTBELT_KEY, or SMS_GATEWAY in env vars.');
};

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN: verifyOtp(phone, purpose, code) → true or throws
// ═══════════════════════════════════════════════════════════════════════════════
const verifyOtp = (phone, purpose, code) => {
  phone = normalise(phone);
  const key    = genKey(phone, purpose);
  const record = otpStore.get(key);

  if (!record) throw Object.assign(new Error('OTP not found or expired.'), { code: 'NOT_FOUND' });

  if (Date.now() > record.expiresAt) {
    otpStore.delete(key);
    throw Object.assign(new Error('OTP has expired.'), { code: 'EXPIRED' });
  }

  record.attempts++;
  if (record.attempts > OTP_MAX_TRIES) {
    otpStore.delete(key);
    throw Object.assign(new Error('Too many incorrect attempts.'), { code: 'MAX_ATTEMPTS' });
  }

  // Timing-safe comparison
  const expected = record.hash;
  const actual   = hashOtp(String(code));
  const match    = expected.length === actual.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));

  if (!match) {
    const left = OTP_MAX_TRIES - record.attempts;
    throw Object.assign(
      new Error(`Invalid OTP. ${left > 0 ? left + ' attempt(s) remaining.' : 'Account locked.'}`),
      { code: 'INVALID', attemptsLeft: left }
    );
  }

  otpStore.delete(key);   // single-use
  logger.info(`[SMS] OTP verified for ${maskPhone(phone)} (purpose: ${purpose})`);
  return true;
};

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN API — check provider status
// ═══════════════════════════════════════════════════════════════════════════════
const getProviderStatus = () => ({
  twilio:        !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
  fast2sms:      !!process.env.FAST2SMS_KEY,
  textbelt:      !!process.env.TEXTBELT_KEY,
  emailGateway:  !!(process.env.EMAIL_USER && process.env.SMS_GATEWAY),
  anyConfigured: !!(
    process.env.TWILIO_ACCOUNT_SID ||
    process.env.FAST2SMS_KEY        ||
    process.env.TEXTBELT_KEY        ||
    (process.env.EMAIL_USER && process.env.SMS_GATEWAY)
  ),
});

// ─── Utilities ────────────────────────────────────────────────────────────────
const maskPhone  = (p) => p.replace(/(\+\d{1,3})\d+(\d{4})/, '$1*****$2');

const buildMessage = (otp, purpose) => {
  const expiry = process.env.OTP_EXPIRY_MINS || 10;
  const labels = {
    verify:   'Your SecureAuth verification code',
    reset:    'Your SecureAuth password reset code',
    login:    'Your SecureAuth login code',
  };
  const label = labels[purpose] || 'Your SecureAuth code';
  return `${label}: ${otp}\nExpires in ${expiry} mins. Never share this code.`;
};

// Cleanup expired OTPs every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore.entries()) {
    if (now > v.expiresAt) otpStore.delete(k);
  }
}, 5 * 60 * 1000);

module.exports = {
  sendOtp,
  verifyOtp,
  getProviderStatus,
  maskPhone,
  CARRIER_GATEWAYS,
};
