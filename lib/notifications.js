const nodemailer = require('nodemailer');
const logger = require('./logger');

// ─── Email Transport ─────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: { rejectUnauthorized: true },
});

// ─── Twilio SMS ───────────────────────────────────────────────────────────────
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  const twilio = require('twilio');
  twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
}

// ─── Send Email ───────────────────────────────────────────────────────────────
const sendEmail = async ({ to, subject, html }) => {
  if (!process.env.EMAIL_USER) {
    logger.warn(`[DEV] Email to ${to}: ${subject}`);
    return true;
  }
  await transporter.sendMail({
    from: process.env.EMAIL_FROM || `SecureAuth <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
  });
  logger.info(`Email sent to ${to}`);
};

// ─── Send SMS ─────────────────────────────────────────────────────────────────
const sendSMS = async (to, body) => {
  if (!twilioClient) {
    logger.warn(`[DEV] SMS to ${to}: ${body}`);
    return true;
  }
  await twilioClient.messages.create({
    body,
    from: process.env.TWILIO_PHONE,
    to,
  });
  logger.info(`SMS sent to ${to}`);
};

// ─── Email Templates ──────────────────────────────────────────────────────────
const emailTemplate = (title, content) => `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0a0f; font-family:'Segoe UI',sans-serif; color:#e0e0e0; }
  .wrap { max-width:560px; margin:40px auto; background:#12121a; border:1px solid #2a2a3a; border-radius:16px; overflow:hidden; }
  .header { background:linear-gradient(135deg,#6c3bff,#3b82f6); padding:32px; text-align:center; }
  .header h1 { font-size:24px; font-weight:700; color:#fff; letter-spacing:2px; }
  .body { padding:40px; }
  .otp-box { background:#1e1e2e; border:1px solid #6c3bff; border-radius:12px; text-align:center; padding:24px; margin:24px 0; }
  .otp { font-size:42px; font-weight:800; letter-spacing:12px; color:#6c3bff; font-family:monospace; }
  .note { font-size:13px; color:#888; margin-top:8px; }
  p { line-height:1.7; color:#ccc; margin-bottom:16px; }
  .footer { text-align:center; padding:20px; border-top:1px solid #2a2a3a; font-size:12px; color:#555; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header"><h1>🔐 SECURE AUTH</h1></div>
  <div class="body">
    <p style="font-size:20px;font-weight:600;color:#fff;margin-bottom:8px;">${title}</p>
    ${content}
  </div>
  <div class="footer">This is an automated message. Do not reply. &copy; ${new Date().getFullYear()} SecureAuth</div>
</div>
</body>
</html>
`;

const sendVerificationOtp = async (email, otp) => {
  const content = `
    <p>Welcome! Please verify your email address using the OTP below.</p>
    <div class="otp-box">
      <div class="otp">${otp}</div>
      <div class="note">Expires in ${process.env.OTP_EXPIRY_MINS || 10} minutes. Never share this code.</div>
    </div>
    <p>If you didn't request this, please ignore this email.</p>
  `;
  await sendEmail({ to: email, subject: 'Verify Your Email — SecureAuth', html: emailTemplate('Email Verification', content) });
};

const sendResetOtp = async (email, otp) => {
  const content = `
    <p>We received a password reset request. Use the OTP below to proceed.</p>
    <div class="otp-box">
      <div class="otp">${otp}</div>
      <div class="note">Expires in ${process.env.OTP_EXPIRY_MINS || 10} minutes. Never share this code.</div>
    </div>
    <p>If you didn't request a password reset, please secure your account immediately.</p>
  `;
  await sendEmail({ to: email, subject: 'Password Reset OTP — SecureAuth', html: emailTemplate('Password Reset', content) });
};

const sendWelcomeEmail = async (email, name) => {
  const content = `
    <p>Hello <strong style="color:#fff">${name}</strong>,</p>
    <p>Your account has been successfully verified and activated. You can now log in.</p>
    <p style="color:#6c3bff;font-weight:600;">Stay safe. Never share your password with anyone.</p>
  `;
  await sendEmail({ to: email, subject: 'Welcome to SecureAuth 🎉', html: emailTemplate('Account Activated!', content) });
};

module.exports = { sendVerificationOtp, sendResetOtp, sendWelcomeEmail, sendSMS };
