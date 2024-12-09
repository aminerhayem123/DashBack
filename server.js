require('dotenv').config();
const express = require('express');
const cors = require('cors'); // Import cors
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
app.use(express.urlencoded({ extended: true }));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
// Enable CORS
app.use(cors());
// Middleware
app.use(bodyParser.json());
// Apply helmet middleware to set the Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],  // Allow content from same origin
      styleSrc: ["'self'", "https://fonts.googleapis.com"],  // Allow styles from Google Fonts
      fontSrc: ["'self'", "https://fonts.gstatic.com"],  // Allow fonts from Google Fonts
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts (if required)
    },
  })
);
// Add these queries at the top level of your file
const STORE_RESET_TOKEN_QUERY = `
  UPDATE users 
  SET reset_token = $1, reset_token_expires = $2 
  WHERE email = $3 
  RETURNING *
`;
const FIND_USER_BY_RESET_TOKEN_QUERY = `
  SELECT * FROM users 
  WHERE reset_token = $1 
  AND reset_token_expires > NOW()
`;
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
// Password Reset Request Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  try {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No user found with this email address.' });
    }
    const user = result.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex'); // Generate a reset token
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour from now
    // Store the reset token and expiration in the database
    await pool.query(STORE_RESET_TOKEN_QUERY, [
      resetToken,
      resetTokenExpires,
      email
    ]);
    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;
    // Send the reset link via email
    const transporter = nodemailer.createTransport({
      service: 'gmail', // or use another email service
      auth: {
        user: process.env.EMAIL_USER, // Your email
        pass: process.env.EMAIL_PASS, // Your email password or app password
      },
    });
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `Click the link to reset your password: ${resetLink}`,
    };
    await transporter.sendMail(mailOptions);
    // Respond with success message
    res.status(200).json({ message: 'Password reset link has been sent to your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error processing password reset request.' });
  }
});
// Password Reset Page - Show Form
app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  res.send(`
    <html>
      <body>
        <form action="/reset-password/${token}" method="POST">
          <input type="password" name="newPassword" placeholder="New Password" required />
          <input type="password" name="confirmPassword" placeholder="Confirm Password" required />
          <button type="submit">Reset Password</button>
        </form>
      </body>
    </html>
  `);
});
// Handle Password Reset
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  try {
    // Find user with valid reset token
    const result = await pool.query(FIND_USER_BY_RESET_TOKEN_QUERY, [token]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }
    const user = result.rows[0];
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    // Update password and clear reset token
    await pool.query(`
      UPDATE users 
      SET password = $1, reset_token = NULL, reset_token_expires = NULL 
      WHERE id = $2
    `, [hashedPassword, user.id]);
    res.status(200).json({ message: 'Password reset successful!' });
  } catch (error) {
    console.error('Error during password reset:', error);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Get Packs Endpoint
app.get('/packs', async (req, res) => {
  try {
    const query = 'SELECT * FROM packs'; // Ensure your table is named 'packs'
    const result = await pool.query(query);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching packs:', error);
    res.status(500).json({ error: 'Failed to fetch packs' });
  }
});

// Profile Endpoint
app.get('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header
  
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id; // Assuming token contains the user id
    
    // Fetch user profile data from the database
    const query = 'SELECT name, email, coins, total_downloads FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    res.status(200).json({
      name: user.name,
      email: user.email,
      totalCoins: user.coins,
      totalDownloads: user.total_downloads,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching profile data' });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
