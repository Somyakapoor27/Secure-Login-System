// middleware/auth.js

// Requires a fully authenticated session (password + 2FA if enabled)
function requireAuth(req, res, next) {
  if (req.session && req.session.userId && !req.session.pending2FA) {
    return next();
  }
  return res.redirect('/login');
}

// Used only on the 2FA verification page itself: user has passed
// password check but must still complete TOTP verification.
function requirePending2FA(req, res, next) {
  if (req.session && req.session.pending2FA) {
    return next();
  }
  return res.redirect('/login');
}

// Redirect already-logged-in users away from login/register pages
function redirectIfAuth(req, res, next) {
  if (req.session && req.session.userId && !req.session.pending2FA) {
    return res.redirect('/dashboard');
  }
  return next();
}

module.exports = { requireAuth, requirePending2FA, redirectIfAuth };
