// server.js
require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');

const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET) {
  console.warn(
    '[WARNING] SESSION_SECRET is not set in your environment. ' +
      'Using an insecure default — set SESSION_SECRET in a .env file before deploying.'
  );
}

// ---- Security headers ----
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], // data: needed for the 2FA QR code
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
    },
  })
);

// Trust first proxy if deployed behind one (needed for secure cookies)
if (IS_PROD) app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Session management ----
// Sessions are tracked server-side by session ID (not just a signed cookie),
// so logout / expiry are enforced immediately and can't be replayed by
// tampering with the client. Uses the default in-memory store, which is
// fine for local use/single-instance deployments; for production with
// multiple server instances, swap in a shared store (Redis, etc.) — see
// README.
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me',
    name: 'sid', // avoid the default 'connect.sid' fingerprint
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // JS on the page can't read the cookie (mitigates XSS cookie theft)
      secure: IS_PROD, // only sent over HTTPS in production
      sameSite: 'lax', // CSRF mitigation for top-level navigations
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// ---- Routes ----
app.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));
app.use('/', authRoutes);

// 404
app.use((req, res) => {
  res.status(404).render('404');
});

// Central error handler — never leak stack traces to the client
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong.');
});

app.listen(PORT, () => {
  console.log(`Secure login app running at http://localhost:${PORT}`);
});
