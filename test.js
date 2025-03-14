// Backend (server.js)
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

// Initialize express app
const app = express();

// Middleware
const corsOptions = {
  origin: 'http://localhost:3000', // Allow frontend URL
  credentials: true, // Allow cookies/auth headers
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

// Setup PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || 'your_db_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'your_db_name',
  password: process.env.DB_PASSWORD || 'your_db_password',
  port: process.env.DB_PORT || 5432,
});

// ✅ User Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const result = await pool.query('SELECT id, email, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, 'your-jwt-secret', { expiresIn: '1h' });
    res.json({ message: 'Login successful!', token, user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
