// reset-users.js - one-time script to reset the users table with plain password column
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const sql = `
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name TEXT,
  email TEXT UNIQUE NOT NULL,
  password TEXT,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- seed admin
INSERT INTO users (name, email, password, role)
VALUES ('Admin', 'aluminiportalddvscm@gmail.com', 'ddvsc@123', 'admin');
`;

(async () => {
  try {
    console.log('Running reset-users...');
    await pool.query(sql);
    console.log('✅ users table reset and admin seeded');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error running reset-users:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
})();
