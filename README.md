# 🔐 SecureAuth — Production-Grade Auth System

A fully secured, single-page Login / Registration / Forgot Password system with dual-factor OTP verification (Email + SMS) built for Railway deployment.

---

## 🛡️ Security Features

| Attack Vector | Mitigation |
|---|---|
| Brute Force | Rate limiting (express-rate-limit) + account lockout |
| SQL/NoSQL Injection | express-mongo-sanitize + input validation |
| XSS | Helmet CSP + xss sanitization on all inputs |
| CSRF | SameSite=Strict cookies + session regeneration |
| Session Fixation | Session regenerated on login |
| Password Enumeration | Timing-safe responses + generic messages |
| HTTP Parameter Pollution | hpp middleware |
| Clickjacking | X-Frame-Options: DENY via Helmet |
| Weak Passwords | Strength meter + regex enforcement |
| OTP Leakage | OTPs hashed with SHA-256 before storage |
| Replay Attacks | OTP expiry (10 min) + single-use |
| Credential Stuffing | Progressive lockout (5 attempts → 30 min) |
| Man-in-the-Middle | HSTS preload enforced |
| Overly Verbose Errors | Generic error messages in production |
| Large Payload Attacks | Body parser limit: 10kb |

---

## 🔄 Authentication Flow

```
REGISTRATION (3-step)
  ① Submit form → server creates user + sends Email OTP
  ② Enter Email OTP → server marks email verified + sends SMS OTP  
  ③ Enter SMS OTP  → account activated ✓

LOGIN
  → Email + password → session issued (httpOnly cookie)

FORGOT PASSWORD (3-step)
  ① Enter email → Email OTP sent
  ② Verify Email OTP → SMS OTP sent
  ③ Verify SMS OTP  → set new password
```

---

## 🚀 Deploy to Railway

### Prerequisites
- [Railway account](https://railway.app)
- MongoDB Atlas cluster (free tier works)
- Gmail account with App Password OR SendGrid
- Twilio account for SMS (free trial works)

### Step 1 — Clone and push to GitHub
```bash
git init
git add .
git commit -m "initial commit"
gh repo create secure-auth --public --push
```

### Step 2 — Create Railway project
1. Go to [railway.app](https://railway.app) → **New Project**
2. Select **Deploy from GitHub repo**
3. Choose your repository

### Step 3 — Set Environment Variables in Railway
Go to your service → **Variables** tab and add:

```
PORT=3000
NODE_ENV=production
APP_URL=https://your-app.up.railway.app

MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/authdb

JWT_SECRET=<generate: openssl rand -hex 64>
SESSION_SECRET=<generate: openssl rand -hex 64>

EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your@gmail.com
EMAIL_PASS=your_gmail_app_password
EMAIL_FROM=SecureAuth <your@gmail.com>

TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_PHONE=+1234567890

BCRYPT_ROUNDS=12
OTP_EXPIRY_MINS=10
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINS=30
```

### Step 4 — Deploy
Railway auto-deploys on push. Your app will be live at:
`https://your-app.up.railway.app`

---

## 📧 Email Setup (Gmail)

1. Enable 2FA on your Gmail account
2. Go to **Google Account → Security → App Passwords**
3. Generate an app password for "Mail"
4. Use that 16-char password as `EMAIL_PASS`

---

## 📱 SMS Setup (Twilio)

1. Sign up at [twilio.com](https://twilio.com)
2. Get a free phone number
3. Copy Account SID, Auth Token, and your Twilio number

---

## 🗄️ MongoDB Setup (Atlas)

1. Create free cluster at [mongodb.com/atlas](https://mongodb.com/atlas)
2. Create database user with password
3. Whitelist all IPs: `0.0.0.0/0` (Railway IPs change)
4. Get connection string and replace in `MONGODB_URI`

---

## 💻 Local Development

```bash
# Install dependencies
npm install

# Copy env template
cp .env.example .env
# Edit .env with your values

# Start dev server
node server.js

# Open http://localhost:3000
```

**Without email/SMS config:** OTPs are printed to the server console for testing.

---

## 🏗️ Project Structure

```
auth-system/
├── server.js              # Express app + security middleware
├── routes/
│   └── auth.js            # All auth endpoints
├── models/
│   └── User.js            # Mongoose user schema
├── middleware/
│   └── validate.js        # Input validation + XSS sanitization
├── lib/
│   ├── db.js              # MongoDB connection
│   ├── logger.js          # Winston logger
│   ├── memStore.js        # In-memory store (dev/demo)
│   └── notifications.js   # Email + SMS service
├── public/
│   └── index.html         # Single-page frontend
├── railway.json           # Railway deployment config
├── nixpacks.toml          # Build config
└── .env.example           # Environment template
```

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/verify-email` | Verify email OTP |
| POST | `/api/auth/verify-phone` | Verify phone OTP |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET  | `/api/auth/me` | Check session |
| POST | `/api/auth/forgot-password` | Request reset |
| POST | `/api/auth/verify-reset-email` | Verify reset email OTP |
| POST | `/api/auth/verify-reset-phone` | Verify reset SMS OTP |
| POST | `/api/auth/reset-password` | Set new password |
| POST | `/api/auth/resend-otp` | Resend any OTP |

---

## 🔑 Generating Secure Secrets

```bash
# JWT Secret
openssl rand -hex 64

# Session Secret  
openssl rand -hex 64
```

---

## 📝 License
MIT
