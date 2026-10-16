const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'keshav_studio_secret_key_2026'; // Change in production

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const db = new sqlite3.Database('./keshav_studio.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to SQLite database: keshav_studio.db');
});

// Initialize Database Tables & Default Admin User
db.serialize(() => {
  // 1. Users Table (for Authentication)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  // Create default admin user (Username: admin, Password: adminpassword) if not exists
  db.get(`SELECT * FROM users WHERE username = 'admin'`, [], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync('adminpassword', 10);
      db.run(`INSERT INTO users (username, password, role) VALUES ('admin', ?, 'owner')`, [hashedPassword]);
      console.log('Default Admin Account Created: [Username: admin | Password: adminpassword]');
    }
  });

  // 2. Invoices Table
  db.run(`CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_number TEXT UNIQUE,
    client_name TEXT,
    client_phone TEXT,
    total_amount REAL,
    advance_paid REAL,
    balance_due REAL,
    date TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Auth Middleware to Protect Routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access Denied: Please login first' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session token' });
    req.user = user;
    next();
  });
};

// --- AUTH API ROUTES ---

// Admin Login Route
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(400).json({ error: 'Invalid Username or Password' });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid Username or Password' });

    // Generate Auth Token
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });

    res.json({
      message: 'Login successful!',
      token: token,
      user: { username: user.username, role: user.role }
    });
  });
});

// --- PROTECTED INVOICE API ROUTES ---

// 1. Get All Invoices
app.get('/api/invoices', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM invoices ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ invoices: rows });
  });
});

// 2. Save New Invoice
app.post('/api/invoices', authenticateToken, (req, res) => {
  const { inv_number, client_name, client_phone, total_amount, advance_paid, balance_due, date } = req.body;

  const query = `INSERT INTO invoices (inv_number, client_name, client_phone, total_amount, advance_paid, balance_due, date) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

  db.run(query, [inv_number, client_name, client_phone, total_amount, advance_paid, balance_due, date], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Invoice saved successfully!', id: this.lastID, inv_number });
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Keshav Photo Arts Studio ERP running at http://localhost:${PORT}`);
});