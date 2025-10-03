// fix.js — one-time DB patch to add password_hash column if missing
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Render requires SSL
});

(async () => {
  try {
    console.log("Connecting to DB...");
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;`);
    console.log("✅ password_hash column ensured");
  } catch (err) {
    console.error("❌ Fix error:", err);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();
