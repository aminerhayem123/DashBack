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
    const query = 'SELECT name, email, coins, total_downloads, total_purchases FROM users WHERE id = $1';
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
      totalPurchases: user.total_purchases,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching profile data' });
  }
});

// Create a transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  service: 'gmail', // or use another email service like SendGrid or SMTP
  auth: {
    user: process.env.EMAIL_USER, // your email address
    pass: process.env.EMAIL_PASS, // your email password
  },
});
// purshase coins Email
const sendConfirmationEmail = (userEmail, userName) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: 'Order Confirmation - Your Purchase Request',
    html: `
      <h2>Hello, ${userName}</h2>
      <p>We have received your order for the pack. Please ensure you complete the money transfer within 3 days.</p>
      <p>Make sure to include your email in the bank transaction so we can match the payment with your order.</p>
      <p>Thank you for trusting our service!</p>
    `,
  };

  return transporter.sendMail(mailOptions);
};
// Get all dashboards
app.get('/dashboards', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM dashboards');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching dashboards:', err);
    res.status(500).json({ error: 'Failed to fetch dashboards' });
  }
});
// Get a single dashboard by ID
app.get('/dashboards/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM dashboards WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Dashboard not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching dashboard:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});
// Get a single dashboard by ID
app.post('/purchasedash', async (req, res) => {
  const { dashboardIds } = req.body;  // Removed total, we will calculate it based on dashboardIds
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'No token provided.' });
  }

  if (!dashboardIds || dashboardIds.length === 0) {
    return res.status(400).json({ error: 'No dashboard IDs provided.' });
  }

  try {
    // Verify token and fetch user
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Fetch user coins
    const userQuery = 'SELECT coins, total_purchases FROM users WHERE id = $1';
    const userResult = await pool.query(userQuery, [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const userCoins = userResult.rows[0].coins;

    // Fetch dashboards and calculate total
    const dashboardQuery = `
      SELECT id, price_coins
      FROM dashboards
      WHERE id = ANY($1::int[])
    `;
    const dashboardResult = await pool.query(dashboardQuery, [dashboardIds]);

    if (dashboardResult.rows.length !== dashboardIds.length) {
      return res.status(400).json({ error: 'Some dashboards were not found.' });
    }

    const total = dashboardResult.rows.reduce((sum, dashboard) => sum + dashboard.price_coins, 0);

    // Check if the user has enough coins
    if (userCoins < total) {
      return res.status(400).json({ error: 'Insufficient coins for this purchase.' });
    }

    // Start a transaction
    await pool.query('BEGIN');
    try {
      // Deduct coins from user
      await pool.query('UPDATE users SET coins = coins - $1 WHERE id = $2', [total, userId]);

      // Insert purchases for each dashboard
      for (const dashboard of dashboardResult.rows) {
        // Insert the purchase record
        await pool.query(
          `INSERT INTO purchases (user_id, dashboard_id, purchased_at) 
           VALUES ($1, $2, NOW())`,
          [userId, dashboard.id]
        );
      }

      // Increment the total_purchases counter
      await pool.query(
        'UPDATE users SET total_purchases = total_purchases + $1 WHERE id = $2',
        [dashboardIds.length, userId]
      );

      // Commit the transaction
      await pool.query('COMMIT');
      res.status(200).json({ message: 'Purchase successful!' });
    } catch (error) {
      // Rollback in case of error
      await pool.query('ROLLBACK');
      console.error(error);
      res.status(500).json({ error: 'Failed to complete the purchase.' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to complete the purchase.' });
  }
});
// Profile Purchase History Endpoint
app.get('/profile/purchase-history', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    const query = `
      SELECT p.id, p.purchased_at, d.name, d.price_coins, d.preview_url, d.demo_url, 
             d.technical_details, d.features
      FROM purchases p
      JOIN dashboards d ON p.dashboard_id = d.id
      WHERE p.user_id = $1
      ORDER BY p.purchased_at DESC
    `;
    const result = await pool.query(query, [userId]);

    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching purchase history' });
  }
});

// Middleware to check if user is admin
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'super_user') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Get all purchase requests
app.get('/purchase-requests', authMiddleware, async (req, res) => {
  try {
    const query = `
      SELECT 
        pr.id,
        pr.status,
        pr.created_at,
        u.name as user_name,
        u.email as user_email,
        p.name as pack_name,
        p.nb_coins as pack_coins,
        p.price as pack_price
      FROM purchase_requests pr
      JOIN users u ON pr.user_id = u.id
      JOIN packs p ON pr.pack_id = p.id
      WHERE pr.status = 'pending'
      ORDER BY pr.created_at DESC
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching purchase requests:', error);
    res.status(500).json({ error: 'Failed to fetch purchase requests' });
  }
});

// Create purchase request
app.post('/purchase', async (req, res) => {
  const { packId, name, email } = req.body;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Start a transaction
    await pool.query('BEGIN');

    // Create purchase request
    const insertQuery = `
      INSERT INTO purchase_requests (user_id, pack_id, status)
      VALUES ($1, $2, 'pending')
      RETURNING id
    `;
    await pool.query(insertQuery, [userId, packId]);

    // Send confirmation email
    await sendConfirmationEmail(email, name);

    await pool.query('COMMIT');
    res.status(200).json({ message: 'Purchase request created successfully!' });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error processing purchase:', error);
    res.status(500).json({ error: 'Failed to complete the purchase request.' });
  }
});

// Approve purchase request
app.post('/purchase-requests/:id/approve', authMiddleware, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query('BEGIN');

    // Get the purchase request details
    const requestQuery = `
      SELECT pr.*, p.nb_coins, u.id as user_id
      FROM purchase_requests pr
      JOIN packs p ON pr.pack_id = p.id
      JOIN users u ON pr.user_id = u.id
      WHERE pr.id = $1 AND pr.status = 'pending'
    `;
    const requestResult = await pool.query(requestQuery, [id]);

    if (requestResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Purchase request not found or already processed' });
    }

    const request = requestResult.rows[0];

    // Add coins to user's account
    await pool.query(
      'UPDATE users SET coins = coins + $1 WHERE id = $2',
      [request.nb_coins, request.user_id]
    );

    // Update request status
    await pool.query(
      'UPDATE purchase_requests SET status = $1 WHERE id = $2',
      ['approved', id]
    );

    await pool.query('COMMIT');
    res.json({ message: 'Purchase request approved successfully' });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error approving purchase request:', error);
    res.status(500).json({ error: 'Failed to approve purchase request' });
  }
});

// Reject purchase request
app.post('/purchase-requests/:id/reject', authMiddleware, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'UPDATE purchase_requests SET status = $1 WHERE id = $2 AND status = $3 RETURNING id',
      ['rejected', id, 'pending']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Purchase request not found or already processed' });
    }

    res.json({ message: 'Purchase request rejected successfully' });
  } catch (error) {
    console.error('Error rejecting purchase request:', error);
    res.status(500).json({ error: 'Failed to reject purchase request' });
  }
});

module.exports = { sendConfirmationEmail };
// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
