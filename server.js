require('dotenv').config();
const express = require('express');
const cors = require('cors'); // Import cors
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

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
  

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
