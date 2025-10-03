// migrate.js — minimal safe improvements
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/alumni';

if (!process.env.DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL not set. Falling back to local postgres connection string.');
  console.warn('If you intend to run this against your Render Postgres, set DATABASE_URL and re-run.');
}

const pool = new Pool({
  connectionString,
  // Use SSL in production (Render requires SSL). In local dev this will be false.
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const sql = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_activity (
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  email TEXT,
  when_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_messages (
  id SERIAL PRIMARY KEY,
  name TEXT,
  email TEXT,
  message TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;

(async () => {
  try {
    console.log('Connecting to database:', connectionString.replace(/\/\/.*:/, '//*****:')); // mask credential display
    await pool.query(sql);
    console.log('✅ Migration applied successfully');
    process.exit(0);
  } catch (err) {
    console.error('❌ Migration error:', err && err.stack ? err.stack : err);
    process.exit(1);
  } finally {
    try {
      await pool.end();
    } catch (e) {
      // ignore pool shutdown errors
    }
  }
})();
