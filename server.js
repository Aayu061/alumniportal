// server.js — Alumni Portal backend (PostgreSQL + bcrypt + auto-migration)
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = process.env.SECRET || '4d8a24573616cf553f3144fd5e7b5e5b'; // your JWT secret
const MIGRATE_SECRET = process.env.MIGRATE_SECRET || '0edebaa651c498bde0e7a7634a49ad87ac85ab5bc6538442';

// --- Middleware ---
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['https://aayu061.github.io', 'https://aayu061.github.io/alumniportal'],
  })
);

// --- PostgreSQL connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Helper for queries
async function dbQuery(text, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// JWT generator
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    SECRET,
    { expiresIn: '7d' }
  );
}

// --- Ensure users table & required columns ---
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
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
    console.log('✅ Users table verified and required columns ensured (password_hash, role)');
  } catch (err) {
    console.error('Failed to ensure users table or columns:', err);
  }
})();

// --- Migration endpoint (protected) ---
app.post('/internal/migrate-add-password-hash', async (req, res) => {
  const secretHeader = (req.headers['x-migrate-secret'] || '').toString();
  if (secretHeader !== MIGRATE_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
    return res.json({ ok: true, message: 'password_hash and role columns ensured' });
  } catch (err) {
    console.error('Migration failed:', err);
    return res.status(500).json({ ok: false, error: 'migration failed', detail: String(err) });
  }
});

// --- Seed admin user if missing ---
(async () => {
  try {
    const adminEmail = 'aluminiportalddvscm@gmail.com';
    const adminPassword = 'ddvsc@123';
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [adminEmail]);
    if (!existing.rows.length) {
      const hash = await bcrypt.hash(adminPassword, 10);
      await dbQuery(
        `INSERT INTO users (name, email, password_hash, role, created_at)
         VALUES ($1, $2, $3, 'admin', NOW())`,
        ['Admin', adminEmail, hash]
      );
      console.log('✅ Admin seeded successfully');
    } else {
      console.log('✅ Admin already exists');
    }
  } catch (err) {
    console.error('Error seeding admin:', err);
  }
})();

// --- Health check ---
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// --- Register route ---
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

// --- Login route ---
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
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    }

    // fallback (plaintext legacy users)
    if (user.password && user.password === password) {
      try {
        const newHash = await bcrypt.hash(password, 10);
        await dbQuery('UPDATE users SET password_hash = $1, password = NULL WHERE id = $2', [
          newHash,
          user.id,
        ]);
        console.log(`Auto-upgraded password for user id=${user.id}`);
      } catch (uerr) {
        console.error('Failed to auto-upgrade hashed password:', uerr);
      }

      const token = generateToken(user);
      return res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    }

    return res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- 404 fallback ---
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// --- Start server ---
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  try {
    await dbQuery('SELECT 1');
    console.log('Connected to PostgreSQL successfully');
  } catch (err) {
    console.error('Postgres connection test failed:', err);
  }
});
