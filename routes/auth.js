// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const db = require('../db/db');
const { requireAuth, requirePending2FA, redirectIfAuth } = require('../middleware/auth');

const router = express.Router();

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

// ---- Prepared statements (parameterized -> no SQL injection) ----
const findByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const findByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findById = db.prepare('SELECT * FROM users WHERE id = ?');
const insertUser = db.prepare(
  'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
);
const setTotpSecret = db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?');
const enableTotp = db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?');
const disableTotp = db.prepare(
  'UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?'
);
const bumpFailedAttempts = db.prepare(
  'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?'
);
const resetFailedAttempts = db.prepare(
  'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?'
);
const setLockout = db.prepare('UPDATE users SET locked_until = ? WHERE id = ?');

// ---- Rate limiting on auth endpoints (slows down brute force / credential stuffing) ----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts from this device. Please try again later.',
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many accounts created from this device. Please try again later.',
});

// ---------------- Helpers ----------------

function passwordRules() {
  return body('password')
    .isLength({ min: 10 })
    .withMessage('Password must be at least 10 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain a lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain an uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain a number');
}

// ---------------- Register ----------------

router.get('/register', redirectIfAuth, (req, res) => {
  res.render('register', { errors: [], values: {} });
});

router.post(
  '/register',
  redirectIfAuth,
  registerLimiter,
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be 3-30 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username may only contain letters, numbers, and underscores')
      .escape(),
    body('email')
      .trim()
      .isEmail()
      .withMessage('A valid email address is required')
      .normalizeEmail(),
    passwordRules(),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const { username, email } = req.body;

    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        errors: errors.array(),
        values: { username, email },
      });
    }

    try {
      if (findByUsername.get(username)) {
        return res.status(400).render('register', {
          errors: [{ msg: 'That username is already taken' }],
          values: { username, email },
        });
      }
      if (findByEmail.get(email)) {
        return res.status(400).render('register', {
          errors: [{ msg: 'That email is already registered' }],
          values: { username, email },
        });
      }

      // Password hashing with bcrypt (salted automatically, cost factor 12)
      const passwordHash = await bcrypt.hash(req.body.password, BCRYPT_ROUNDS);
      insertUser.run(username, email, passwordHash);

      return res.redirect('/login?registered=1');
    } catch (err) {
      console.error('Registration error:', err.message);
      return res.status(500).render('register', {
        errors: [{ msg: 'Something went wrong. Please try again.' }],
        values: { username, email },
      });
    }
  }
);

// ---------------- Login ----------------

router.get('/login', redirectIfAuth, (req, res) => {
  res.render('login', {
    errors: [],
    values: {},
    registered: req.query.registered === '1',
  });
});

router.post(
  '/login',
  redirectIfAuth,
  loginLimiter,
  [
    body('username').trim().notEmpty().withMessage('Username is required').escape(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    const { username, password } = req.body;
    const genericError = 'Invalid username or password';

    if (!errors.isEmpty()) {
      return res.status(400).render('login', { errors: errors.array(), values: { username } });
    }

    try {
      const user = findByUsername.get(username);

      // Always compare against a hash even if user not found, to reduce
      // timing differences that reveal whether a username exists.
      const dummyHash = '$2b$12$C6UzMDM.H6dfI/f/IKcEeOWlH6Z8ELQq7bZQeQ4c4o5s6h9g6d9pu';
      const hashToCheck = user ? user.password_hash : dummyHash;

      if (user && user.locked_until && user.locked_until > Date.now()) {
        const minsLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
        return res.status(429).render('login', {
          errors: [{ msg: `Account temporarily locked. Try again in ${minsLeft} minute(s).` }],
          values: { username },
        });
      }

      const passwordMatches = await bcrypt.compare(password, hashToCheck);

      if (!user || !passwordMatches) {
        if (user) {
          bumpFailedAttempts.run(user.id);
          const updated = findById.get(user.id);
          if (updated.failed_attempts >= MAX_FAILED_ATTEMPTS) {
            setLockout.run(Date.now() + LOCKOUT_MS, user.id);
          }
        }
        return res.status(401).render('login', {
          errors: [{ msg: genericError }],
          values: { username },
        });
      }

      // Successful password check
      resetFailedAttempts.run(user.id);

      // Regenerate the session on privilege change to prevent session fixation
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration error:', err.message);
          return res.status(500).render('login', {
            errors: [{ msg: 'Something went wrong. Please try again.' }],
            values: { username },
          });
        }

        if (user.totp_enabled) {
          // Password correct, but 2FA still required before full login
          req.session.pending2FA = true;
          req.session.pendingUserId = user.id;
          return res.redirect('/2fa/verify');
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        return res.redirect('/dashboard');
      });
    } catch (err) {
      console.error('Login error:', err.message);
      return res.status(500).render('login', {
        errors: [{ msg: 'Something went wrong. Please try again.' }],
        values: { username },
      });
    }
  }
);

// ---------------- Logout ----------------

router.post('/logout', (req, res) => {
  const cookieName = req.session.cookie ? 'connect.sid' : null;
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err.message);
    if (cookieName) res.clearCookie(cookieName);
    res.redirect('/login');
  });
});

// ---------------- Dashboard ----------------

router.get('/dashboard', requireAuth, (req, res) => {
  const user = findById.get(req.session.userId);
  res.render('dashboard', { user });
});

// ---------------- 2FA setup (enable) ----------------

router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = findById.get(req.session.userId);
  if (user.totp_enabled) {
    return res.redirect('/dashboard');
  }

  const secret = speakeasy.generateSecret({
    name: `SecureLoginApp (${user.username})`,
  });

  setTotpSecret.run(secret.base32, user.id);
  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  res.render('2fa-setup', { qrDataUrl, secret: secret.base32, errors: [] });
});

router.post(
  '/2fa/setup',
  requireAuth,
  [body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Enter the 6-digit code')],
  async (req, res) => {
    const user = findById.get(req.session.userId);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({
          secret: user.totp_secret,
          label: user.username,
          encoding: 'base32',
        })
      );
      return res.status(400).render('2fa-setup', {
        qrDataUrl,
        secret: user.totp_secret,
        errors: errors.array(),
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({
          secret: user.totp_secret,
          label: user.username,
          encoding: 'base32',
        })
      );
      return res.status(400).render('2fa-setup', {
        qrDataUrl,
        secret: user.totp_secret,
        errors: [{ msg: 'Incorrect code. Please try again.' }],
      });
    }

    enableTotp.run(user.id);
    res.redirect('/dashboard');
  }
);

router.post('/2fa/disable', requireAuth, (req, res) => {
  disableTotp.run(req.session.userId);
  res.redirect('/dashboard');
});

// ---------------- 2FA verify (during login) ----------------

router.get('/2fa/verify', requirePending2FA, (req, res) => {
  res.render('2fa-verify', { errors: [] });
});

router.post(
  '/2fa/verify',
  requirePending2FA,
  loginLimiter,
  [body('token').trim().isLength({ min: 6, max: 6 }).isNumeric().withMessage('Enter the 6-digit code')],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('2fa-verify', { errors: errors.array() });
    }

    const user = findById.get(req.session.pendingUserId);
    if (!user) {
      return res.redirect('/login');
    }

    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).render('2fa-verify', {
        errors: [{ msg: 'Incorrect code. Please try again.' }],
      });
    }

    // Fully authenticated now — regenerate session again and clear pending flags
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err.message);
        return res.status(500).render('2fa-verify', {
          errors: [{ msg: 'Something went wrong. Please try again.' }],
        });
      }
      req.session.userId = user.id;
      req.session.username = user.username;
      res.redirect('/dashboard');
    });
  }
);

module.exports = router;
