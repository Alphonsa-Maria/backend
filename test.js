const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
require('dotenv').config();

const router = express.Router();
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

console.log("Test.js is working!");

// ✅ Test Route to Check if test.js is Working
router.get('/test', (req, res) => {
  res.send('Test.js is working!');
});

// ✅ Middleware to verify JWT token
const authenticateUser = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// ✅ Admin Login Route
router.post('/admin-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const admin = result.rows[0];
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ adminId: admin.id, email: admin.email }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ message: 'Admin login successful!', token });
  } catch (error) {
    console.error('Error during admin login:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Configure Nodemailer with Gmail App Password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.ADMIN_EMAIL, // Your admin email
    pass: process.env.APP_PASSWORD, // Your generated app password
  },
});

// ✅ Admin Sends Update & Notifies All Users
router.post('/admin/send-update', async (req, res) => {
  const { updateText } = req.body;

  if (!updateText) {
    return res.status(400).json({ message: 'Update text is required.' });
  }

  try {
    // ✅ Save Update in Database
    await pool.query('INSERT INTO admin_updates (update_text) VALUES ($1)', [updateText]);

    // ✅ Get All Users' Emails
    const users = await pool.query('SELECT email FROM users');
    const emailList = users.rows.map(user => user.email);

    if (emailList.length === 0) {
      return res.json({ message: 'Update saved but no users found to notify.' });
    }

    // ✅ Send Email Notification to Users
    const mailOptions = {
      from: process.env.ADMIN_EMAIL,
      to: emailList.join(','),
      subject: 'New Update from Admin',
      text: `Dear User,\n\n${updateText}\n\nBest Regards,\nLancer Team`
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'Update sent and email notifications sent successfully!' });
  } catch (error) {
    console.error('Error sending update:', error);
    res.status(500).json({ message: 'Server error.' });
  }

  
  
});

module.exports = router;