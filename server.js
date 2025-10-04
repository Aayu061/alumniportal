// server.js - bcrypt-ready with auto-upgrade from plaintext
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.SECRET;

if (!SECRET) {
  console.error("FATAL: SECRET env var is not set. Set SECRET in Render env vars and redeploy.");
  process.exit(1);
}

// --- Crash reporting ---
process.on('unhandledRejection', (reason, p) => {
  console.error('UNHANDLED REJECTION at:', p, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  // optional: process.exit(1);
});

// Allowed origins (only origin form)
const allowedOrigins = [
  'https://aayu061.github.io'
];

app.use(cors({ origin: allowedOrigins }));
app.use(bodyParser.json());

// --- Postgres pool ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function dbQuery(text, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '7d' });
}

// Ensure users table and password_hash column exist (safe startup migration)
(async () => {
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
    // In case table existed without password_hash (older schema)
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    console.log("✅ Users table verified and password_hash ensured");
  } catch (err) {
    console.error("Failed to ensure users table or column:", err);
    // continue; handlers will surface errors on requests
  }
})();

// --- Routes ---

// Register (stores hashed password; does NOT keep plaintext password)
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

// Login (tries password_hash; if absent, falls back to plaintext and auto-upgrades)
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
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // If password_hash present, verify it.
    if (user.password_hash) {
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

      const token = generateToken(user);
      return res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    // Fallback: compare plaintext (existing rows). If ok, auto-upgrade to hashed password.
    if (user.password && user.password === password) {
      try {
        const newHash = await bcrypt.hash(password, 10);
        await dbQuery('UPDATE users SET password_hash = $1, password = NULL WHERE id = $2', [newHash, user.id]);
        console.log(`Auto-upgraded password for user id=${user.id} to hashed password`);
      } catch (uerr) {
        console.error('Failed to auto-upgrade hashed password:', uerr);
        // Not fatal — proceed to issue token anyway if plaintext matched
      }

      const token = generateToken(user);
      return res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }

    // If no match
    return res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Example protected route stub (optional)
app.get('/api/me', async (req, res) => {
  res.json({ message: 'Add JWT middleware to protect this route' });
});

// Fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Start
app.listen(PORT, () => {
  console.log('🚀 Server running on port', PORT);
});
