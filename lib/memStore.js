// In-memory store for demo/dev when MongoDB is not configured
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const users = new Map();
const sessions = new Map();

class MemUser {
  constructor(data) {
    Object.assign(this, data);
    this.loginAttempts = 0;
    this.lockUntil = null;
    this.emailVerified = false;
    this.phoneVerified = false;
    this.isActive = false;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }
  get isLocked() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
  }
  async comparePassword(candidate) {
    return bcrypt.compare(candidate, this.password);
  }
  async incLoginAttempts() {
    const max = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
    const lockMins = parseInt(process.env.LOCKOUT_MINS) || 30;
    if (this.lockUntil && this.lockUntil < Date.now()) {
      this.loginAttempts = 1;
      this.lockUntil = null;
    } else {
      this.loginAttempts++;
      if (this.loginAttempts >= max) {
        this.lockUntil = new Date(Date.now() + lockMins * 60 * 1000);
      }
    }
    users.set(this.email, this);
  }
  async resetLoginAttempts() {
    this.loginAttempts = 0;
    this.lockUntil = null;
    users.set(this.email, this);
  }
  async save() {
    this.updatedAt = new Date();
    users.set(this.email, this);
    return this;
  }
}

const memStore = {
  isActive: () => !process.env.MONGODB_URI,
  async findByEmail(email) {
    return users.get(email.toLowerCase()) || null;
  },
  async create(data) {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    const hashed = await bcrypt.hash(data.password, rounds);
    const user = new MemUser({ ...data, email: data.email.toLowerCase(), password: hashed });
    users.set(user.email, user);
    return user;
  },
  async findByResetToken(token) {
    for (const u of users.values()) {
      if (u.resetToken === token) return u;
    }
    return null;
  },
};

module.exports = memStore;
