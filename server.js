require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const { connectDB } = require('./lib/db');
const logger = require('./lib/logger');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Trust Proxy (Railway sits behind a proxy) ───────────────────────────────
app.set('trust proxy', 1);

// ─── Security Headers via Helmet ────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ─── Compression ─────────────────────────────────────────────────────────────
app.use(compression());

// ─── Body Parsers ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ─── CORS ────────────────────────────────────────────────────────────────────
const allowedOrigins = [process.env.APP_URL, `http://localhost:${PORT}`].filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // same-site / mobile
    if (allowedOrigins.includes(origin) || /\.railway\.app$/.test(origin))
      return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST'],
}));

// ─── NoSQL Injection Prevention ──────────────────────────────────────────────
app.use(mongoSanitize());

// ─── HTTP Parameter Pollution Prevention ─────────────────────────────────────
app.use(hpp());

// ─── Session (memorystore keeps it clean in prod without MongoDB) ────────────
const MemoryStore = require('memorystore')(session);
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: new MemoryStore({ checkPeriod: 86400000 }), // prune expired every 24h
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    maxAge: 15 * 60 * 1000,
  },
  name: 'sid',
}));

// ─── Global Rate Limiters ────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// ─── Static Files (assets only — HTML served dynamically for CSP nonce) ──────
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: true,
  index: false,
}));

// ─── Routes ──────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);

// ─── Health Check — always 200 so Railway never kills the container ──────────
app.get('/health', (req, res) => {
  const { getStatus } = require('./lib/db');
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    db: process.env.MONGODB_URI ? (getStatus() ? 'connected' : 'connecting') : 'memstore',
    ts: Date.now(),
  });
});

// ─── Serve SPA with nonce injected so CSP allows inline scripts ───────────────
const fs = require('fs');
const indexPath = path.join(__dirname, 'views', 'index.html');
let indexCache = null;
app.get('/', (req, res) => {
  if (!indexCache || process.env.NODE_ENV !== 'production') {
    indexCache = fs.readFileSync(indexPath, 'utf8');
  }
  const html = indexCache.replace('{{NONCE}}', res.locals.nonce);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(html);
});

// ─── 404 & Error Handler ─────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, next) => {
  logger.error(err.stack);
  const status = err.status || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
  res.status(status).json({ error: message });
});

// ─── Start — HTTP server starts FIRST, DB connects after ────────────────────
// This ensures Railway healthcheck passes even if DB is slow to connect.
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server running on port ${PORT}`);
});

// DB connects asynchronously — app stays up regardless
connectDB()
  .then(() => logger.info('Database ready'))
  .catch(err => {
    logger.error('DB connection failed — running in memStore fallback mode:', err.message);
    // Do NOT exit — keep serving so healthcheck passes and Railway shows logs
  });

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => process.exit(0));
});

module.exports = app;
