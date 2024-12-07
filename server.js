require('dotenv').config();
const express = require('express');
const cors = require('cors'); // Import cors
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
// Enable CORS
app.use(cors());
// Middleware
app.use(bodyParser.json());

// Sign-Up Endpoint
app.post('/signup', async (req, res) => {
    console.log("Received signup request:", req.body);  // Add this log to verify the request body
    const { name, email, password } = req.body;
  
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
  
    try {
      const emailCheckQuery = 'SELECT * FROM users WHERE email = $1';
      const existingUser = await pool.query(emailCheckQuery, [email]);
  
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Email already exists.' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10); // Hash password
      const insertUserQuery = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *';
      const result = await pool.query(insertUserQuery, [name, email, hashedPassword, 'sample_user']);
      
      res.status(201).json({ message: 'User created successfully!', user: result.rows[0] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to create user.' });
    }
  });
  
// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET, // You should define a secret key in your .env file
      { expiresIn: '1h' } // Token expiration time
    );

    // Respond with token and user info
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
