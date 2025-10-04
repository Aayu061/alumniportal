// server.js — Permanent, self-healing Alumni Portal backend
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 10000;

// --- Secrets (loaded from Render env or fallback) ---
const SECRET = process.env.SECRET || '4d8a24573616cf553f3144fd5e7b5e5b';

// --- Middleware ---
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['https://aayu061.github.io', 'https://aayu061.github.io/alumniportal'],
  })
);

// --- PostgreSQL Connection ---
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

// --- JWT Helper ---
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, {
    expiresIn: '7d',
  });
}

// --- Ensure Schema ---
(async () => {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        password_hash TEXT,
        role TEXT DEFAULT 'user'
      );
    `);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
    // Fix old schema: make sure password can be NULL (for bcrypt-only systems)
    await dbQuery(`ALTER TABLE users ALTER COLUMN password DROP NOT NULL;`);
    console.log('✅ Users table and schema fully ensured');
  } catch (err) {
    console.error('Schema ensure failed:', err);
  }
})();

// --- Self-healing Admin Seeder (permanent & automatic, uses upsert) ---
(async () => {
  try {
    const adminEmail = 'aluminiportalddvscm@gmail.com';
    const adminPassword = 'ddvsc@123';

    // Always compute fresh hash and upsert the admin row.
    // This avoids duplicate-key errors and guarantees the admin exists with the expected password hash.
    const hash = await bcrypt.hash(adminPassword, 10);

    await dbQuery(
      `
      INSERT INTO users (name, email, password_hash, role, created_at)
      VALUES ($1, $2, $3, 'admin', NOW())
      ON CONFLICT (email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            role = 'admin'
      `,
      ['Admin', adminEmail, hash]
    );

    console.log('✅ Admin upserted (created or updated) successfully');
  } catch (err) {
    console.error('Admin upsert failed:', err);
  }
})();

// --- Routes ---

// Health
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// Register (for users)
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length)
      return res.status(409).json({ error: 'Email already registered' });

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

// Login (for admin and users)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: 'Missing fields' });

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

    // Legacy plaintext fallback
    if (user.password && user.password === password) {
      const newHash = await bcrypt.hash(password, 10);
      await dbQuery('UPDATE users SET password_hash = $1, password = NULL WHERE id = $2', [
        newHash,
        user.id,
      ]);
      console.log(`Auto-upgraded password for user id=${user.id}`);
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

// 404
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



