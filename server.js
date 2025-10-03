// server.js - plain password version (quick fix, not secure)
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.SECRET || 'alumni_secret_key';

// Allowed origins
const allowedOrigins = [
  'https://aayu061.github.io',
  'https://aayu061.github.io/alumniportal'
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

// Ensure table exists with plain `password` column
(async () => {
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
  console.log("✅ Users table ensured with plain password column");
})();

// --- Routes ---
// Register
app.post('/api/register', async (req, res) => {
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
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const normalized = email.trim().toLowerCase();
  const result = await dbQuery('SELECT id, name, email, password, role FROM users WHERE email = $1', [normalized]);
  const user = result.rows[0];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({ message: 'Login successful', token, user });
});

// Fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Start
app.listen(PORT, () => console.log('🚀 Server running on port', PORT));
