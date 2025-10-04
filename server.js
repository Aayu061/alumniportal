// server.js — Clean production-ready backend for Alumni Portal
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = process.env.SECRET || 'change_this_secret_in_render_env';
const MIGRATE_SECRET = process.env.MIGRATE_SECRET || 'change_this_migrate_secret_in_render_env';

// --- Basic guards ---
if (!SECRET || SECRET === 'change_this_secret_in_render_env') {
  console.warn('WARNING: Using default SECRET. Please set SECRET in Render environment variables.');
}

// --- Middleware ---
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['https://aayu061.github.io', 'https://aayu061.github.io/alumniportal'],
  })
);

// --- Postgres pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function dbQuery(text, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// --- JWT helper ---
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    SECRET,
    { expiresIn: '7d' }
  );
}

// --- Ensure users table and required columns (safe startup migration) ---
(async function ensureSchema() {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        password_hash TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
    console.log('✅ Users table and required columns ensured');
  } catch (err) {
    console.error('Schema ensure failed:', err);
  }
})();

// --- Auto-seed admin at startup if missing (one-time safe seed) ---
(async function seedAdminIfMissing() {
  try {
    const adminEmail = 'aluminiportalddvscm@gmail.com';
    const adminPassword = 'ddvsc@123'; // rotate in Render env if desired
    const res = await dbQuery('SELECT id FROM users WHERE email = $1', [adminEmail]);
    if (!res.rows.length) {
      const hash = await bcrypt.hash(adminPassword, 10);
      await dbQuery(
        `INSERT INTO users (name, email, password_hash, role, created_at)
         VALUES ($1, $2, $3, 'admin', NOW())`,
        ['Admin', adminEmail, hash]
      );
      console.log('✅ Admin seeded at startup');
    } else {
      console.log('✅ Admin already exists');
    }
  } catch (err) {
    console.error('Admin seeding error:', err);
  }
})();

// --- Routes ---

// Health
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const insert = await dbQuery(
      `INSERT INTO users (name, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, email, role`,
      [name.trim(), normalized, hash, 'user']
    );
    res.json({ message: 'Registered successfully', user: insert.rows[0] });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    const result = await dbQuery(
      'SELECT id, name, email, password, password_hash, role FROM users WHERE email = $1',
      [normalized]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.password_hash) {
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

      const token = generateToken(user);
      return res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
      });
    }

    // fallback for legacy plaintext password
    if (user.password && user.password === password) {
      try {
        const newHash = await bcrypt.hash(password, 10);
        await dbQuery('UPDATE users SET password_hash = $1, password = NULL WHERE id = $2', [
          newHash,
          user.id,
        ]);
        console.log(`Auto-upgraded password for user id=${user.id}`);
      } catch (uerr) {
        console.error('Auto-upgrade failed:', uerr);
      }
      const token = generateToken(user);
      return res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
      });
    }

    return res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 404 fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Start
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  try {
    await dbQuery('SELECT 1');
    console.log('Connected to PostgreSQL successfully');
  } catch (err) {
    console.error('Postgres connection test failed:', err);
  }
});
