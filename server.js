// Express + SQLite3 backend for Alumni Portal
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.SECRET || 'alumni_secret_key';

// Allow CORS for GitHub Pages (user + project) and localhost
const allowedOrigins = [
  'https://aayu061.github.io',                 // user site (if used)
  'https://aayu061.github.io/alumniportal',    // <-- ADD THIS (project Pages origin)
  'https://aayu861.github.io',                 // keep if you actually use this too
  'https://aayu861.github.io/alumniportal',    // optional: same for other username/project
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://localhost:3001'
];


app.use(cors({
  origin: function (origin, callback) {
    console.log('[CORS] incoming Origin:', origin);
    // allow requests with no origin (curl, server-to-server)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      console.log('[CORS] origin allowed:', origin);
      return callback(null, true);
    }

    console.log('[CORS] origin NOT allowed:', origin);
    // Do NOT pass an Error object here — return false so the preflight still responds correctly.
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));
app.use(bodyParser.json());


// ------------------ Database setup: Postgres (preferred) with SQLite fallback ------------------
const { Pool } = require('pg');

let pool = null;
let db = null;                         // <-- ADD this line

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  pool.connect()
    .then(() => console.log('✅ Connected to PostgreSQL'))
    .catch(err => console.error('❌ PostgreSQL connection error:', err));

  (async () => {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          is_admin BOOLEAN DEFAULT false
        );
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS login_activity (
          id SERIAL PRIMARY KEY,
          user_id INTEGER,
          email TEXT,
          name TEXT,
          time TIMESTAMP
        );
      `);

   const r = await pool.query('SELECT id FROM users WHERE email = $1', ['aluminiportalddvscm@gmail.com']);
   if (r.rows.length === 0) {
     const hash = bcrypt.hashSync('ddvsc@123', 10);
     await pool.query(
      'INSERT INTO users (name, email, password, is_admin) VALUES ($1,$2,$3,$4)',
      ['Admin', 'aluminiportalddvscm@gmail.com', hash, true]
    );
  }
      console.log('Postgres tables ensured');
    } catch (err) {
      console.error('Error ensuring Postgres tables:', err);
    }
  })();

} else {
  // Fall back to existing SQLite DB (unchanged behavior)
  db = new sqlite3.Database('./alumni.db', (err) => {  // <-- changed 'const db' -> 'db ='
    if (err) throw err;
    console.log('Connected to SQLite database.');
  });

  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS login_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email TEXT,
      name TEXT,
      time TEXT
    )`);
    // Ensure admin exists
    db.get('SELECT * FROM users WHERE email = ?', ['aluminiportalddvscm@gmail.com'], (err, row) => {
      if (!row) {
        const hash = bcrypt.hashSync('ddvsc@123', 10);
        db.run('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, 1)', ['Admin', 'aluminiportalddvscm@gmail.com', hash]);
     }
   });
});

  // optional: keep global reference (not required if db is in outer scope)
  global.sqliteDb = db;
}

// Register (works with Postgres pool OR SQLite db)
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required.' });
  const lowerEmail = email.toLowerCase();
  const hash = bcrypt.hashSync(password, 10);

  // Postgres path
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        await pool.query(
          'INSERT INTO users (name, email, password) VALUES ($1,$2,$3)',
          [name, lowerEmail, hash]
        );
        return res.json({ success: true });
      } catch (err) {
        console.error('[REGISTER][PG]', err && err.message);
        // unique violation -> email already registered
        if (err && (err.code === '23505' || err.constraint === 'users_email_key')) {
          return res.status(400).json({ error: 'Email already registered.' });
        }
        return res.status(500).json({ error: 'Server error.' });
      }
    })();
    return;
  }

  // SQLite fallback
  if (typeof db !== 'undefined' && db) {
    db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, lowerEmail, hash], function(err) {
      if (err) {
        console.error('[REGISTER][SQLITE]', err && err.message);
        return res.status(400).json({ error: 'Email already registered.' });
      }
      return res.json({ success: true });
    });
    return;
  }

  // no DB available
  console.error('[REGISTER] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

// Login (works with Postgres pool OR SQLite db)
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  const lowerEmail = email.toLowerCase();

  // Postgres
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        const r = await pool.query('SELECT * FROM users WHERE email = $1', [lowerEmail]);
        const user = r.rows[0];
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials.' });

        // best-effort activity insert
        try {
          await pool.query('INSERT INTO login_activity (user_id, email, name, time) VALUES ($1,$2,$3,$4)', [
            user.id, user.email, user.name, new Date().toISOString()
          ]);
        } catch (ae) {
          console.error('[LOGIN][PG] activity insert failed:', ae && ae.message);
        }

        const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, SECRET, { expiresIn: '2h' });
        return res.json({ token, name: user.name, email: user.email, is_admin: user.is_admin });
      } catch (err) {
        console.error('[LOGIN][PG] unexpected error:', err && err.message);
        return res.status(500).json({ error: 'Server error during login.' });
      }
    })();
    return;
  }

  // SQLite fallback
  if (typeof db !== 'undefined' && db) {
    try {
      db.get('SELECT * FROM users WHERE email = ?', [lowerEmail], (err, user) => {
        if (err) {
          console.error('[LOGIN][SQLITE] db.get error:', err && err.message);
          return res.status(500).json({ error: 'Server error during login.' });
        }
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials.' });

        // best-effort activity logging
        db.run('INSERT INTO login_activity (user_id, email, name, time) VALUES (?, ?, ?, ?)', [
          user.id, user.email, user.name, new Date().toISOString()
        ], (iErr) => { if (iErr) console.error('[LOGIN][SQLITE] activity insert:', iErr && iErr.message); });

        const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, SECRET, { expiresIn: '2h' });
        return res.json({ token, name: user.name, email: user.email, is_admin: user.is_admin });
      });
    } catch (err) {
      console.error('[LOGIN][SQLITE] catch:', err && err.message);
      return res.status(500).json({ error: 'Server error during login.' });
    }
    return;
  }

  console.error('[LOGIN] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

function requireAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth || typeof auth !== 'string') return res.status(401).json({ error: 'No token.' });
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return res.status(401).json({ error: 'Invalid authorization format.' });
    const token = parts[1];
    const decoded = jwt.verify(token, SECRET);
    if (!decoded || !decoded.is_admin) return res.status(403).json({ error: 'Admin only.' });
    req.user = decoded;
    next();
  } catch (err) {
    console.error('[AUTH] requireAdmin error:', err && err.message);
    return res.status(401).json({ error: 'Invalid token.' });
  }
}

// Get all users (admin only) — works with Postgres or SQLite
app.get('/api/users', requireAdmin, (req, res) => {
  // Postgres
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        const r = await pool.query('SELECT id, name, email, is_admin FROM users ORDER BY id');
        return res.json(r.rows);
      } catch (err) {
        console.error('[USERS][PG]', err && err.message);
        return res.status(500).json({ error: 'Failed to fetch users.' });
      }
    })();
    return;
  }

  // SQLite fallback
  if (typeof db !== 'undefined' && db) {
    db.all('SELECT id, name, email, is_admin FROM users ORDER BY id', [], (err, rows) => {
      if (err) {
        console.error('[USERS][SQLITE]', err && err.message);
        return res.status(500).json({ error: 'Failed to fetch users.' });
      }
      return res.json(rows);
    });
    return;
  }

  console.error('[USERS] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

// Get login activity (admin only) — works with Postgres or SQLite
app.get('/api/activity', requireAdmin, (req, res) => {
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        const r = await pool.query('SELECT id, user_id, email, name, time FROM login_activity ORDER BY id DESC');
        return res.json(r.rows);
      } catch (err) {
        console.error('[ACTIVITY][PG]', err && err.message);
        return res.status(500).json({ error: 'Failed to fetch activity.' });
      }
    })();
    return;
  }

  if (typeof db !== 'undefined' && db) {
    db.all('SELECT id, user_id, email, name, time FROM login_activity ORDER BY id DESC', [], (err, rows) => {
      if (err) {
        console.error('[ACTIVITY][SQLITE]', err && err.message);
        return res.status(500).json({ error: 'Failed to fetch activity.' });
      }
      return res.json(rows);
    });
    return;
  }

  console.error('[ACTIVITY] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

// Admin backup (returns users + activity) — Postgres or SQLite
app.get('/api/admin/backup', requireAdmin, (req, res) => {
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        const u = await pool.query('SELECT id, name, email, is_admin FROM users ORDER BY id');
        const a = await pool.query('SELECT id, user_id, email, name, time FROM login_activity ORDER BY id');
        return res.json({ users: u.rows, activity: a.rows });
      } catch (err) {
        console.error('[BACKUP][PG]', err && err.message);
        return res.status(500).json({ error: 'Failed to create backup.' });
      }
    })();
    return;
  }

  if (typeof db !== 'undefined' && db) {
    db.all('SELECT id, name, email, is_admin FROM users ORDER BY id', [], (uErr, users) => {
      if (uErr) {
        console.error('[BACKUP][SQLITE] users error:', uErr && uErr.message);
        return res.status(500).json({ error: 'Failed to read users.' });
      }
      db.all('SELECT id, user_id, email, name, time FROM login_activity ORDER BY id', [], (aErr, activity) => {
        if (aErr) {
          console.error('[BACKUP][SQLITE] activity error:', aErr && aErr.message);
          return res.status(500).json({ error: 'Failed to read activity.' });
        }
        return res.json({ users, activity });
      });
    });
    return;
  }

  console.error('[BACKUP] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

// Admin restore (accepts { users:[], activity:[] }) — Postgres or SQLite
app.post('/api/admin/restore', requireAdmin, (req, res) => {
  const payload = req.body;
  if (!payload || !Array.isArray(payload.users) || !Array.isArray(payload.activity)) {
    return res.status(400).json({ error: 'Invalid backup format. Expect { users:[], activity:[] }' });
  }

  // Postgres path
  if (typeof pool !== 'undefined' && pool) {
    (async () => {
      try {
        await pool.query('BEGIN');
        for (const u of payload.users) {
          await pool.query(
            `INSERT INTO users (id, name, email, password, is_admin)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (email) DO NOTHING`,
            [u.id || null, u.name || '', (u.email || '').toLowerCase(), u.password || '', u.is_admin ? true : false]
          );
        }
        for (const a of payload.activity) {
          await pool.query(
            `INSERT INTO login_activity (id, user_id, email, name, time)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
            [a.id || null, a.user_id || null, a.email || '', a.name || '', a.time || new Date().toISOString()]
          );
        }
        await pool.query('COMMIT');
        return res.json({ success: true, message: 'Restore completed.' });
      } catch (err) {
        await pool.query('ROLLBACK').catch(()=>{});
        console.error('[RESTORE][PG] failed:', err && err.message);
        return res.status(500).json({ error: 'Restore failed.' });
      }
    })();
    return;
  }

  // SQLite path
  if (typeof db !== 'undefined' && db) {
    try {
      db.serialize(() => {
        const uStmt = db.prepare('INSERT OR IGNORE INTO users (id, name, email, password, is_admin) VALUES (?, ?, ?, ?, ?)');
        for (const u of payload.users) {
          uStmt.run(u.id || null, u.name || '', (u.email || '').toLowerCase(), u.password || '', u.is_admin ? 1 : 0);
        }
        uStmt.finalize();

        const aStmt = db.prepare('INSERT OR IGNORE INTO login_activity (id, user_id, email, name, time) VALUES (?, ?, ?, ?, ?)');
        for (const a of payload.activity) {
          aStmt.run(a.id || null, a.user_id || null, a.email || '', a.name || '', a.time || new Date().toISOString());
        }
        aStmt.finalize();
      });
      return res.json({ success: true, message: 'Restore queued. Existing rows skipped if duplicate.' });
    } catch (err) {
      console.error('[RESTORE][SQLITE] failed:', err && err.message);
      return res.status(500).json({ error: 'Restore failed.' });
    }
  }

  console.error('[RESTORE] no database available');
  return res.status(500).json({ error: 'Server misconfiguration: no database available.' });
});

// ------------------ Contact Form (send email) ------------------
const nodemailer = require('nodemailer');

app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'All fields required.' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.MAIL_USER || 'aluminiportalddvscm@gmail.com',
        pass: process.env.MAIL_PASS  // Gmail App Password
      }
    });

    await transporter.sendMail({
      from: `"Alumni Portal Contact" <${email}>`,
      to: 'aluminiportalddvscm@gmail.com',
      subject: `New contact form message from ${name}`,
      text: message,
      html: `<p><b>Name:</b> ${name}</p>
             <p><b>Email:</b> ${email}</p>
             <p><b>Message:</b><br>${message}</p>`
    });

    return res.json({ success: true, message: 'Your message has been sent!' });
  } catch (err) {
    console.error('[CONTACT] send error:', err && err.message);
    return res.status(500).json({ error: 'Failed to send message.' });
  }
});

app.listen(PORT, () => console.log('Server running on port', PORT));









