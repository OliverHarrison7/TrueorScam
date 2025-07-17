const express = require('express');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// Middleware to parse JSON requests
app.use(express.json());

// Test endpoint
app.get('/test', (req, res) => {
  res.json({ message: 'TrueOrScam backend running' });
});

// Check endpoint (placeholder for scam detection)
app.post('/check', (req, res) => {
  const { type, content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'No content provided' });
  }
  res.json({ verdict: 'UNSAFE', explanation: 'Placeholder response' });
});

// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});