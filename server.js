// server.js - PostgreSQL backend (plain password version, NOT secure!)
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;

// IMPORTANT: set SECRET env var on Render (and locally in dev)
const SECRET = process.env.SECRET || 'alumni_secret_key';

// CORS: allowed origins (add your production origins if different)
const defaultAllowed = [
  'https://aayu061.github.io',
  'https://aayu061.github.io/alumniportal',
];

let allowedOrigins = defaultAllowed;
if (process.env.ALLOWED_ORIGINS) {
  const more = process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
  allowedOrigins = Array.from(new Set([...allowedOrigins, ...more]));
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'CORS not allowed from this origin';
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

// --- Setup tables (plain password) ---
async function setupDB() {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS login_activity (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        email TEXT,
        when_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Seed admin
    const adminEmail = 'aluminiportalddvscm@gmail.com';
    const adminPass = 'ddvsc@123';
    const adminName = 'Admin';

    await dbQuery(
      `INSERT INTO users (name, email, password, role, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (email)
       DO UPDATE SET password = EXCLUDED.password, role = EXCLUDED.role`,
      [adminName, adminEmail, adminPass, 'admin']
    );

    console.log("✅ Tables ensured, admin user seeded");
  } catch (err) {
    console.error("❌ DB setup error:", err.message);
  }
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
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const insert = await dbQuery(
      `INSERT INTO users (name, email, password, role, created_at)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, email, role`,
      [name.trim(), normalized, password, 'user']
    );

    res.json({ message: 'Registered successfully', user: insert.rows[0] });
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
    const result = await dbQuery('SELECT id, name, email, password, role FROM users WHERE email = $1', [normalized]);
    const user = result.rows[0];
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Log login activity
    try {
      await dbQuery('INSERT INTO login_activity (user_id, email, when_ts) VALUES ($1, $2, NOW())', [user.id, user.email]);
    } catch (logErr) {
      console.warn('Failed to log login activity:', logErr.message);
    }

    const token = generateToken(user);
    res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Contact
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body || {};
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });

    await dbQuery('INSERT INTO contact_messages (name, email, message, created_at) VALUES ($1, $2, $3, NOW())',
      [name.trim(), email.trim().toLowerCase(), message.trim()]);
    res.json({ message: 'Message received. Thank you!' });
  } catch (err) {
    console.error('Contact error:', err);
    res.status(500).json({ error: 'Failed to save message' });
  }
});

// Admin only endpoints
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const r = await dbQuery('SELECT id, name, email, role, created_at FROM users ORDER BY id DESC');
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

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

// Start server after DB setup
(async () => {
  await setupDB();
  app.listen(PORT, () => console.log('Server running on port', PORT));
})();
