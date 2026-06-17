const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.error('❌ MySQL Connection Error:', err);
    console.log('💡 Make sure XAMPP MySQL is running!');
    return;
  }
  console.log('✅ MySQL Connected Successfully');
});

// ===== CREATE TABLES =====
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS leads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    source VARCHAR(50) DEFAULT 'website',
    status ENUM('new', 'contacted', 'converted') DEFAULT 'new',
    follow_up_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    lead_id INT NOT NULL,
    text TEXT NOT NULL,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE
  )
`);

// ===== AUTH MIDDLEWARE =====
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length > 0) return res.status(400).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const token = jwt.sign({ id: result.insertId, username }, process.env.JWT_SECRET);
      res.status(201).json({ token, user: { id: result.insertId, username } });
    });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = results[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username } });
  });
});

// ===== LEAD ROUTES =====
app.get('/api/leads', auth, (req, res) => {
  db.query(`
    SELECT l.*, (SELECT COUNT(*) FROM notes n WHERE n.lead_id = l.id) as notes_count
    FROM leads l ORDER BY l.created_at DESC
  `, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

app.get('/api/leads/:id', auth, (req, res) => {
  db.query('SELECT * FROM leads WHERE id = ?', [req.params.id], (err, leadResults) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (leadResults.length === 0) return res.status(404).json({ error: 'Lead not found' });
    
    db.query('SELECT * FROM notes WHERE lead_id = ? ORDER BY created_at DESC', [req.params.id], (err, noteResults) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const lead = leadResults[0];
      lead.notes = noteResults;
      res.json(lead);
    });
  });
});

app.post('/api/leads', auth, (req, res) => {
  const { firstName, lastName, email, phone, source } = req.body;
  if (!firstName || !lastName || !email) {
    return res.status(400).json({ error: 'First name, last name, and email required' });
  }

  db.query(
    'INSERT INTO leads (first_name, last_name, email, phone, source) VALUES (?, ?, ?, ?, ?)',
    [firstName, lastName, email, phone || null, source || 'website'],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      db.query('SELECT * FROM leads WHERE id = ?', [result.insertId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(201).json(results[0]);
      });
    }
  );
});

app.patch('/api/leads/:id/status', auth, (req, res) => {
  const { status } = req.body;
  if (!['new', 'contacted', 'converted'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  db.query('UPDATE leads SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.query('SELECT * FROM leads WHERE id = ?', [req.params.id], (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(results[0]);
    });
  });
});

app.post('/api/leads/:id/notes', auth, (req, res) => {
  const { text, followUpDate } = req.body;
  if (!text) return res.status(400).json({ error: 'Note text required' });

  db.query('SELECT * FROM leads WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'Lead not found' });

    db.query('INSERT INTO notes (lead_id, text, created_by) VALUES (?, ?, ?)',
      [req.params.id, text, req.user.username],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (followUpDate) {
          db.query('UPDATE leads SET follow_up_date = ? WHERE id = ?', [followUpDate, req.params.id]);
        }
        db.query(`
          SELECT l.*, (SELECT COUNT(*) FROM notes n WHERE n.lead_id = l.id) as notes_count
          FROM leads l WHERE l.id = ?
        `, [req.params.id], (err, results) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          res.json(results[0]);
        });
      }
    );
  });
});

app.delete('/api/leads/:id', auth, (req, res) => {
  db.query('DELETE FROM leads WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ message: 'Lead deleted successfully' });
  });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`✅ Using MySQL database`);
});