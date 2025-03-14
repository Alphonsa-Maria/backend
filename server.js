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
app.use(cors());
app.use(bodyParser.json());

// Setup PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// ✅ Middleware to verify JWT token
const authenticateUser = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, 'your-jwt-secret');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// ✅ Fetch all jobs (NEWLY ADDED ROUTE)
app.get('/jobs', async (req, res) => {
    try {
        const jobsList = await pool.query('SELECT * FROM jobs');
        res.json({ jobs: jobsList.rows });
    } catch (error) {
        console.error('Error fetching jobs:', error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// ✅ User Registration Route
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Username, email, and password are required.' });
  }

  try {
    const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Email is already registered.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );

    res.json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
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

// ✅ Profile Update Route (Authenticated Users Only)
app.put('/update-profile', authenticateUser, async (req, res) => {
  let { full_name, mobile, role, bio, industry_interests, social_links } = req.body;
  const userId = req.user.userId;

  try {
    industry_interests = typeof industry_interests === "string" ? JSON.parse(industry_interests) : industry_interests;
    social_links = typeof social_links === "string" ? JSON.parse(social_links) : social_links;

    const query = `
      UPDATE users 
      SET full_name = $1, mobile = $2, role = $3, bio = $4, 
          industry_interests = $5::jsonb, social_links = $6::jsonb
      WHERE id = $7
      RETURNING *;
    `;

    const values = [
      full_name, 
      mobile, 
      role, 
      bio, 
      JSON.stringify(industry_interests), 
      JSON.stringify(social_links), 
      userId
    ];
    
    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found!' });
    }

    res.json({ message: 'Profile updated successfully!', user: result.rows[0] });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Accept a Job (Authenticated Users Only)
app.put('/accept-job/:jobId', authenticateUser, async (req, res) => {
    const jobId = req.params.jobId;
    const userId = req.user.userId;

    try {
        const jobCheck = await pool.query('SELECT * FROM jobs WHERE id = $1', [jobId]);
        if (jobCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Job not found' });
        }

        const result = await pool.query(
            'UPDATE jobs SET accepted_by = $1 WHERE id = $2 RETURNING *',
            [userId, jobId]
        );

        res.json({ message: 'Job accepted successfully!', job: result.rows[0] });
    } catch (error) {
        console.error('Error accepting job:', error);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
