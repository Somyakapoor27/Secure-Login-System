HEAD
# Secure Login System

A self-contained Node.js/Express web app demonstrating a secure username/password
login flow with optional TOTP-based two-factor authentication (2FA).

## Features

- **Password hashing** — bcrypt with a cost factor of 12 (never plaintext, never reversible).
- **SQL injection protection** — all database access goes through `better-sqlite3`
  prepared/parameterized statements; no string concatenation into SQL.
- **Input validation** — `express-validator` enforces username format, email format,
  and password strength (length + mixed case + digit) server-side.
- **Session management** — server-side sessions stored in SQLite (`express-session` +
  `connect-sqlite3`), `httpOnly`, `sameSite=lax` cookies, session ID regenerated on
  login/2FA to prevent session fixation, and a working logout that destroys the session.
- **Brute-force mitigation** — per-IP rate limiting on login/register/2FA endpoints,
  plus per-account lockout after 5 failed attempts (15-minute cooldown).
- **Timing-attack mitigation** — login always runs a bcrypt comparison (against a dummy
  hash when the username doesn't exist) so response time doesn't reveal valid usernames.
- **Security headers** — `helmet` sets a Content-Security-Policy and standard hardening headers.
- **Optional 2FA** — TOTP (Google Authenticator/Authy-compatible) via `speakeasy`,
  with QR-code enrollment (`qrcode`) and a required verification step during login
  when enabled.

## Requirements

- Node.js **22.5 or newer** (the app uses Node's built-in `node:sqlite` module, so
  no native/compiled packages are required — nothing to build, no Python or C++
  build tools needed). Check your version with `node -v`.

## Setup

```bash
npm install
cp .env.example .env
# edit .env and set a real SESSION_SECRET, e.g.:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
npm start
```

Visit `http://localhost:3000`. The SQLite database files are created automatically
in `db/` on first run.

## Project layout

```
server.js            Express app setup, security middleware, session config
db/db.js              SQLite connection + schema (users table)
routes/auth.js         Register / login / logout / 2FA routes
middleware/auth.js     requireAuth / requirePending2FA / redirectIfAuth guards
views/                 EJS templates (register, login, dashboard, 2FA)
public/style.css       Styling
```

## Notes for production use

This is a solid educational/starter foundation, but before shipping to real users
also consider:

- Putting the app behind HTTPS (a load balancer/reverse proxy is fine) — `secure`
  cookies are already enabled automatically when `NODE_ENV=production`.
- Adding CSRF tokens on state-changing forms (e.g. `csrf-csrf` or `csurf` successor)
  if you add cross-origin functionality; `sameSite=lax` already blocks most
  cross-site POST forgeries for this same-origin app.
- Email verification and a password-reset flow (with time-limited, single-use tokens).
- Centralized structured logging/alerting on repeated failed logins.
- Rotating/backing up `SESSION_SECRET` and the SQLite files, or moving to a managed
  database for multi-instance deployments (SQLite sessions don't scale horizontally
  without a shared store).
- Storing 2FA recovery/backup codes so users aren't locked out if they lose their device.
=======

>>>>>>> 48d56edd02e472f4b57043be6f35bb59b5a4a648
