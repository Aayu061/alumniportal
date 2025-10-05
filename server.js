// server.js — Permanent, self-healing Alumni Portal backend (CORS + safe error handler)
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
app.use(
  cors({
    origin: [
      'https://aayu061.github.io',
      'https://aayu061.github.io/alumniportal',
      'http://localhost:3000',
      'http://127.0.0.1:5500'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-migrate-secret',
      'x-seed-secret',
      'Cache-Control'
    ],
    credentials: true,
  })
);

// increase JSON body limit slightly so large backups aren't rejected
app.use(bodyParser.json({ limit: '2mb' }));

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
    // ✅ Ensure users table
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
    await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
    await dbQuery(`ALTER TABLE users ALTER COLUMN password DROP NOT NULL;`);

    // ✅ Ensure login_activity table and columns (fixes when_ts error)
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS login_activity (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        email TEXT,
        when_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await dbQuery(`ALTER TABLE login_activity ADD COLUMN IF NOT EXISTS when_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
    await dbQuery(`ALTER TABLE login_activity ADD COLUMN IF NOT EXISTS email TEXT;`);

    console.log('✅ Users & login_activity tables ensured');
  } catch (err) {
    console.error('Schema ensure failed:', err);
  }
})();

// --- Self-healing Admin Seeder (ensures admin always has valid password) ---
(async () => {
  try {
    const adminEmail = 'aluminiportalddvscm@gmail.com';
    const adminPassword = 'ddvsc@123';
    const hash = await bcrypt.hash(adminPassword, 10);

    // 🩵 If admin exists but missing password_hash, fix it. If not, create.
    await dbQuery(`
      INSERT INTO users (name, email, password_hash, role, created_at)
      VALUES ($1, $2, $3, 'admin', NOW())
      ON CONFLICT (email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            role = 'admin'
    `, ['Admin', adminEmail, hash]);

    console.log('✅ Admin ensured and password reset (email: aluminiportalddvscm@gmail.com)');
  } catch (err) {
    console.error('Admin seeder failed:', err);
  }
})();

// --- Routes ---

// Health
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// Register
// --- Register new user ---
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();

    // 🧩 Check if already registered
    const existing = await dbQuery('SELECT id FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length)
      return res.status(409).json({ error: 'Email already registered' });

    // 🧩 Always hash the password and store in password_hash only
    const hash = await bcrypt.hash(password, 10);
    const insert = await dbQuery(
      `INSERT INTO users (name, email, password_hash, password, role, created_at)
       VALUES ($1, $2, $3, NULL, $4, NOW())
       RETURNING id, name, email, role`,
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
    if (!email || !password)
      return res.status(400).json({ error: 'Missing fields' });

    const normalized = email.trim().toLowerCase();
    const result = await dbQuery(
      'SELECT id, name, email, password, password_hash, role FROM users WHERE email = $1',
      [normalized]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

   // --- Login check (handles both hashed & legacy plain passwords) ---
if (user.password_hash) {
  const ok = await bcrypt.compare(password, user.password_hash);

  // 🧩 If bcrypt fails, try legacy fallback once
  if (!ok && user.password && user.password === password) {
    const newHash = await bcrypt.hash(password, 10);
    await dbQuery('UPDATE users SET password_hash=$1, password=NULL WHERE id=$2', [newHash, user.id]);
  } else if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  await dbQuery('INSERT INTO login_activity (user_id, email, when_ts) VALUES ($1,$2,NOW())', [user.id, user.email]);

  return res.json({
    message: 'Login successful',
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
}

// 🧩 If only plain password exists (old users), convert on first login
if (user.password && user.password === password) {
  const newHash = await bcrypt.hash(password, 10);
  await dbQuery('UPDATE users SET password_hash=$1, password=NULL WHERE id=$2', [newHash, user.id]);
  await dbQuery('INSERT INTO login_activity (user_id, email, when_ts) VALUES ($1,$2,NOW())', [user.id, user.email]);

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

// ✅ Admin endpoint: View login activity
app.get('/api/activity', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let decoded;
    try {
      decoded = jwt.verify(token, SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (decoded.role !== 'admin')
      return res.status(403).json({ error: 'Forbidden: Admin only' });

    const result = await dbQuery(
      'SELECT id, email, when_ts FROM login_activity ORDER BY when_ts DESC LIMIT 50;'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Activity fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Admin-only endpoint: fetch all registered users
app.get('/api/users', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let decoded;
    try {
      decoded = jwt.verify(token, SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (decoded.role !== 'admin')
      return res.status(403).json({ error: 'Forbidden: Admin only' });

    const result = await dbQuery(
      'SELECT id, name, email, role FROM users ORDER BY id ASC;'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Admin-only endpoint: create JSON backup (users + login activity)
app.get('/api/admin/backup', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let decoded;
    try {
      decoded = jwt.verify(token, SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (decoded.role !== 'admin')
      return res.status(403).json({ error: 'Forbidden: Admin only' });

    // ✅ Fetch data
    const users = await dbQuery('SELECT id, name, email, role FROM users ORDER BY id ASC;');
    const activity = await dbQuery('SELECT id, user_id, email, when_ts FROM login_activity ORDER BY when_ts DESC;');

    // ✅ Shape data like backup.json
    const backup = {
      users: users.rows.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        is_admin: u.role === 'admin'
      })),
      activity: activity.rows.map(a => ({
        id: a.id,
        user_id: a.user_id,
        email: a.email,
        time: a.when_ts
      }))
    };
    
    res.json(backup);
  } catch (err) {
    console.error('Backup error:', err);
    res.status(500).json({ error: 'Server error while generating backup' });
  }
});

// ✅ Admin-only endpoint: restore from uploaded backup JSON
// Expects body: { users: [...], activity: [...] }
app.post('/api/admin/restore', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let decoded;
    try { decoded = jwt.verify(token, SECRET); }
    catch { return res.status(401).json({ error: 'Invalid token' }); }

    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden: Admin only' });

    const data = req.body || {};
    const users = Array.isArray(data.users) ? data.users : [];
    const activity = Array.isArray(data.activity) ? data.activity : [];

    // Transactional restore: truncate then insert
    await dbQuery('BEGIN');
    await dbQuery('TRUNCATE TABLE login_activity RESTART IDENTITY CASCADE');
    await dbQuery('TRUNCATE TABLE users RESTART IDENTITY CASCADE');

    // Insert users (passwords not included in backup => leave password_hash NULL)
    for (const u of users) {
      const role = u.is_admin ? 'admin' : 'user';
      await dbQuery(
        `INSERT INTO users (name, email, password_hash, role, created_at)
         VALUES ($1,$2,NULL,$3,NOW())
         ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role`,
        [u.name || null, u.email || null, role]
      );
    }

    // Insert login_activity; link user_id by email if possible
    for (const a of activity) {
      const r = await dbQuery('SELECT id FROM users WHERE email = $1', [a.email]);
      const user_id = r.rows[0] ? r.rows[0].id : null;
      await dbQuery(
        `INSERT INTO login_activity (user_id, email, when_ts)
         VALUES ($1, $2, $3)`,
        [user_id, a.email || null, a.time || new Date()]
      );
    }

    await dbQuery('COMMIT');
    return res.json({ message: 'Restore completed' });
  } catch (err) {
    try { await dbQuery('ROLLBACK'); } catch(e) {}
    console.error('Restore error:', err);
    return res.status(500).json({ error: 'Restore failed' });
  }
});

// --- Global error handler ---
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  try {
    res.status(500).json({ error: 'Server error (see logs)' });
  } catch (e) {
    console.error('Error sending error response', e);
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

