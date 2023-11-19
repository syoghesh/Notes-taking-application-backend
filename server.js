// File: backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/notesdb', { useNewUrlParser: true, useUnifiedTopology: true });

// Create a mongoose model for notes
const Note = mongoose.model('Note', {
  title: String,
  content: String,
  userId: String,
});

// Create a mongoose model for users
const User = mongoose.model('User', {
  username: String,
  email: String,
  password: String,
});

// API endpoint for user registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).send('Username is already taken');
    }

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = await User.create({
      username,
      password: hashedPassword,
    });

    // Return the user data (excluding the password) and a token
    const token = jwt.sign({ userId: newUser._id }, 'secret_key', { expiresIn: '1h' });

    res.json({ user: { _id: newUser._id, username: newUser.username, email: newUser.email }, token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Internal Server Error');
  }
});

// API endpoint for user login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user by username
    const user = await User.findOne({ username });

    // If the user is not found or the password is incorrect, return an error
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid username or password');
    }

    // Return the user data (excluding the password) and a token
    const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });

    res.json({ user: { _id: user._id, username: user.username, email: user.email }, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Internal Server Error');
  }
});

// API endpoint to fetch user-specific notes (secured with middleware)
app.get('/api/notes', authenticateUser, async (req, res) => {
  const userId = req.user.userId;

  try {
    const notes = await Note.find({ userId });
    res.json(notes);
  } catch (error) {
    console.error('Error fetching notes:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Middleware to authenticate the user using the provided token
function authenticateUser(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  jwt.verify(token, 'secret_key', (err, decoded) => {
    if (err) {
      return res.status(401).send('Unauthorized');
    }

    req.user = { userId: decoded.userId };
    next();
  });
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
ss