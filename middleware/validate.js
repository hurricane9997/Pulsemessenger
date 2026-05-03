const validator = require('validator');
const xss = require('xss');

const sanitize = (str) => {
  if (typeof str !== 'string') return '';
  return xss(str.trim().slice(0, 500));
};

const validateRegister = (req, res, next) => {
  const { fullName, email, phone, password, confirmPassword } = req.body;

  const errors = [];

  if (!fullName || sanitize(fullName).length < 2)
    errors.push('Full name must be at least 2 characters');

  if (!email || !validator.isEmail(email))
    errors.push('Valid email is required');

  if (!phone || !validator.isMobilePhone(phone, 'any', { strictMode: false }))
    errors.push('Valid phone number is required');

  if (!password || password.length < 8)
    errors.push('Password must be at least 8 characters');

  const pwdRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=])/;
  if (password && !pwdRegex.test(password))
    errors.push('Password must include uppercase, lowercase, number, and special character');

  if (password !== confirmPassword)
    errors.push('Passwords do not match');

  if (errors.length > 0) return res.status(400).json({ error: errors[0], errors });

  // Sanitize and reattach
  req.body.fullName = sanitize(fullName);
  req.body.email = validator.normalizeEmail(email);
  req.body.phone = sanitize(phone);

  next();
};

const validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !validator.isEmail(email))
    return res.status(400).json({ error: 'Valid email is required' });
  if (!password || typeof password !== 'string' || password.length > 200)
    return res.status(400).json({ error: 'Password is required' });
  req.body.email = validator.normalizeEmail(email);
  next();
};

const validateOtp = (req, res, next) => {
  const { otp } = req.body;
  if (!otp || !/^\d{6}$/.test(otp))
    return res.status(400).json({ error: 'OTP must be a 6-digit number' });
  next();
};

const validatePassword = (req, res, next) => {
  const { password, confirmPassword } = req.body;
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const pwdRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=])/;
  if (!pwdRegex.test(password))
    return res.status(400).json({ error: 'Password must include uppercase, lowercase, number, and special character' });
  if (password !== confirmPassword)
    return res.status(400).json({ error: 'Passwords do not match' });
  next();
};

module.exports = { validateRegister, validateLogin, validateOtp, validatePassword, sanitize };
