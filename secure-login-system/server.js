const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const path = require('path');
const db = require('./database');

const app = express();

// Body parser & static assets
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. Session Configuration (Secure Cookies)
app.use(
  session({
    name: '__SecureSessionId',
    secret: process.env.SESSION_SECRET || 'super-secret-cryptographically-secure-key-32b',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,              // Blocks client-side JS (mitigates XSS cookie theft)
      secure: process.env.NODE_ENV === 'production', // Set true in production over HTTPS
      sameSite: 'strict',          // Strong CSRF protection
      maxAge: 1000 * 60 * 60 * 2   // 2 hours session lifetime
    }
  })
);

// 2. Rate Limiter (Brute-Force Mitigation)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // Limit each IP to 10 requests per window
  message: { error: 'Too many requests. Please try again in 15 minutes.' }
});

// Middleware: Authentication Guard
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// Input Validation Helpers
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return typeof email === 'string' && emailRegex.test(email.trim());
}

function isValidPassword(password) {
  // Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,100}$/;
  return typeof password === 'string' && passwordRegex.test(password);
}

// ================= ROUTES =================

// --- 1. REGISTER ---
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({
        error: 'Password must be 8-100 characters long with at least 1 uppercase, 1 lowercase, and 1 digit.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const existingUser = db.findUserByEmail(cleanEmail);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    // Password hashing via Argon2id
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3
    });

    const newUserId = db.createUser(cleanEmail, passwordHash);

    // Auto-login session creation
    req.session.userId = newUserId;
    res.status(201).json({ message: 'User registered successfully', userId: newUserId });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed due to an internal server error.' });
  }
});

// --- 2. LOGIN ---
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = db.findUserByEmail(cleanEmail);

    // Constant-time mitigation against timing attacks
    if (!user) {
      await argon2.verify('$argon2id$v=19$m=65536,t=3,p=1$fakehashfakehashfakehash$fakehash', 'fakepass');
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const validPassword = await argon2.verify(user.password_hash, password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // If 2FA is active, set temporary pre-auth session
    if (user.two_factor_enabled) {
      req.session.tempUserId = user.id;
      return res.json({ require2FA: true, message: 'Please provide your 2FA TOTP code.' });
    }

    // Full login session established
    req.session.userId = user.id;
    res.json({ message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ error: 'Login error occurred.' });
  }
});

// --- 3. 2FA VERIFICATION (POST-LOGIN) ---
app.post('/api/2fa/verify-login', authLimiter, (req, res) => {
  const { token } = req.body;
  const tempUserId = req.session.tempUserId;

  if (!tempUserId) {
    return res.status(401).json({ error: 'No 2FA pending session found.' });
  }

  const user = db.findUserById(tempUserId);
  const isValid = authenticator.check(token, user.two_factor_secret);

  if (!isValid) {
    return res.status(400).json({ error: 'Invalid authenticator code.' });
  }

  // Clear temp pre-auth and establish verified session
  delete req.session.tempUserId;
  req.session.userId = user.id;

  res.json({ message: '2FA authentication successful' });
});

// --- 4. 2FA SETUP (GENERATE QR CODE) ---
app.get('/api/2fa/setup', requireAuth, async (req, res) => {
  const user = db.findUserById(req.session.userId);
  const secret = authenticator.generateSecret();

  db.saveTemp2FASecret(user.id, secret);

  const otpAuthUrl = authenticator.keyuri(user.email, 'SecureApp', secret);
  const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl);

  res.json({ secret, qrCode: qrCodeDataUrl });
});

// --- 5. 2FA SETUP CONFIRMATION ---
app.post('/api/2fa/confirm-setup', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = db.findUserById(req.session.userId);

  const isValid = authenticator.check(token, user.two_factor_secret);
  if (!isValid) {
    return res.status(400).json({ error: 'Invalid verification code.' });
  }

  db.enable2FA(user.id);
  res.json({ message: 'Two-factor authentication enabled successfully.' });
});

// --- 6. CHECK CURRENT SESSION / USER STATUS ---
app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ authenticated: false });
  }
  const user = db.findUserById(req.session.userId);
  res.json({
    authenticated: true,
    user: { id: user.id, email: user.email, two_factor_enabled: Boolean(user.two_factor_enabled) }
  });
});

// --- 7. LOGOUT (SESSION INVALIDATION) ---
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed.' });
    }
    res.clearCookie('__SecureSessionId');
    res.json({ message: 'Logged out successfully.' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
