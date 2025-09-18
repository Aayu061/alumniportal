// Express + SQLite3 backend for Alumni Portal
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = 'alumni_secret_key';

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
    console.log('[CORS] incoming Origin:', origin);  // NEW

    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) === -1) {
      console.log('[CORS] origin NOT allowed:', origin);  // NEW
      return callback(new Error('CORS not allowed from this origin'), false);
    }

    console.log('[CORS] origin allowed:', origin);  // NEW
    return callback(null, true);
  }
}));
app.use(bodyParser.json());


// SQLite DB setup
const db = new sqlite3.Database('./alumni.db', (err) => {
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
  db.get('SELECT * FROM users WHERE email = ?', ['admin@admin.com'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, 1)', ['Admin', 'admin@admin.com', hash]);
    }
  });
});

// Register
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required.' });
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hash], function(err) {
    if (err) return res.status(400).json({ error: 'Email already registered.' });
    res.json({ success: true });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials.' });
    // Log activity
    db.run('INSERT INTO login_activity (user_id, email, name, time) VALUES (?, ?, ?, ?)', [user.id, user.email, user.name, new Date().toISOString()]);
    // JWT token
    const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, SECRET, { expiresIn: '2h' });
    res.json({ token, name: user.name, email: user.email, is_admin: user.is_admin });
  });
});

// Middleware: verify admin
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token.' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], SECRET);
    if (!decoded.is_admin) return res.status(403).json({ error: 'Admin only.' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token.' });
  }
}

// Get all users (admin only)
app.get('/api/users', requireAdmin, (req, res) => {
  db.all('SELECT id, name, email, is_admin FROM users', [], (err, rows) => {
    res.json(rows);
  });
});

// Get login activity (admin only)
app.get('/api/activity', requireAdmin, (req, res) => {
  db.all('SELECT * FROM login_activity ORDER BY id DESC', [], (err, rows) => {
    res.json(rows);
  });
});

app.listen(PORT, () => console.log('Server running on port', PORT));

