const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 254,
  },
  phone: {
    type: String,
    required: true,
    trim: true,
    maxlength: 20,
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false,
  },

  // Verification
  emailVerified: { type: Boolean, default: false },
  phoneVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: false },

  // OTP fields
  emailOtp: { type: String, select: false },
  emailOtpExpiry: { type: Date, select: false },
  phoneOtp: { type: String, select: false },
  phoneOtpExpiry: { type: Date, select: false },

  // Password reset
  resetToken: { type: String, select: false },
  resetTokenExpiry: { type: Date, select: false },
  resetPhoneOtp: { type: String, select: false },
  resetPhoneOtpExpiry: { type: Date, select: false },

  // Security
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  lastLogin: { type: Date },
  lastLoginIp: { type: String },
  passwordChangedAt: { type: Date },

  // Audit
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Index for performance
userSchema.index({ email: 1 });
userSchema.index({ resetToken: 1 });

// Virtual: is locked?
userSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save: hash password
userSchema.pre('save', async function (next) {
  this.updatedAt = Date.now();
  if (!this.isModified('password')) return next();
  const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  this.password = await bcrypt.hash(this.password, rounds);
  this.passwordChangedAt = Date.now();
  next();
});

// Method: compare password
userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Method: increment login failures
userSchema.methods.incLoginAttempts = async function () {
  const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
  const lockoutMins = parseInt(process.env.LOCKOUT_MINS) || 30;

  if (this.lockUntil && this.lockUntil < Date.now()) {
    // Reset after lockout expires
    this.loginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.loginAttempts += 1;
    if (this.loginAttempts >= maxAttempts) {
      this.lockUntil = new Date(Date.now() + lockoutMins * 60 * 1000);
    }
  }
  return this.save();
};

// Method: reset login attempts on success
userSchema.methods.resetLoginAttempts = function () {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  return this.save();
};

module.exports = mongoose.model('User', userSchema);
