// server.js - PostgreSQL-ready backend for Alumni Portal
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;

// IMPORTANT: set SECRET env var on Render (and locally in dev)
const SECRET = process.env.SECRET || 'alumni_secret_key';

// CORS: allowed origins (add your production origins if different)
const defaultAllowed = [
  'https://aayu061.github.io',
  'https://aayu061.github.io/alumniportal',
  // If you serve frontend from another origin add here
];

const renderBackendOrigin = process.env.BACKEND_ORIGIN; // optional
if (renderBackendOrigin && !defaultAllowed.includes(renderBackendOrigin)) {
  defaultAllowed.push(renderBackendOrigin);
}

// Use ALLOWED_ORIGINS env (comma separated) if supplied
let allowedOrigins = defaultAllowed;
if (process.env.ALLOWED_ORIGINS) {
  const more = process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
  allowedOrigins = Array.from(new Set([...allowedOrigins, ...more]));
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
  origin: function(origin, callback){
    // allow requests with no origin (like mobile apps or curl)
    if(!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));

// --- Postgres pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/alumni',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function dbQuery(text, params = []) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

// Test DB at startup (non-fatal; logs if problem)
(async () => {
  try {
    await pool.query('SELECT 1');
    console.log('Connected to PostgreSQL successfully');
  } catch (err) {
    console.error('Postgres connection error (DB routes will be affected):', err.message || err);
  }
})();

// --- Helpers ---
function generateToken(user) {
  const payload = { id: user.id, email: user.email, role: user.role || 'user' };
  return jwt.sign(payload, SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Authorization header missing' });
  const parts = header.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid auth header' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// --- Routes ---

// Health check
app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(503).json({ status: 'db-unavailable', error: err.message });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    // check duplicate
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 12);
    const insert = await dbQuery(
      `INSERT INTO users (name, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, email, role`,
      [name.trim(), normalized, passwordHash, 'user']
    );
    const user = insert.rows[0];
    res.json({ message: 'Registered successfully', user });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    const result = await dbQuery('SELECT id, name, email, password_hash, role FROM users WHERE email = $1', [normalized]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash || '');
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Log login activity (best-effort)
    try {
      await dbQuery('INSERT INTO login_activity (user_id, email, when_ts) VALUES ($1, $2, NOW())', [user.id, user.email]);
    } catch (logErr) {
      console.warn('Failed to log login activity:', logErr && logErr.message);
    }

    const token = generateToken(user);
    res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Contact form
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body || {};
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });

    await dbQuery('INSERT INTO contact_messages (name, email, message, created_at) VALUES ($1, $2, $3, NOW())', [name.trim(), email.trim().toLowerCase(), message.trim()]);
    res.json({ message: 'Message received. Thank you!' });
  } catch (err) {
    console.error('Contact error:', err);
    res.status(500).json({ error: 'Failed to save message' });
  }
});

// Admin: list users (no password hashes)
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await dbQuery('SELECT id, name, email, role, created_at FROM users ORDER BY id DESC');
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin: login activity (optional)
app.get('/api/activity', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await dbQuery('SELECT id, user_id, email, when_ts FROM login_activity ORDER BY when_ts DESC LIMIT 200');
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/activity error:', err);
    res.status(500).json({ error: 'Failed to fetch activity' });
  }
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
app.listen(PORT, () => console.log('Server running on port', PORT));
