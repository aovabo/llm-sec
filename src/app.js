const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const path = require('path');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const rateLimiter = new RateLimiterMemory({
  points: 10,
  duration: 1
});

// Serve static files
app.use(express.static('public'));

// Dummy agent response template
const dummyAgent = {
  systemInstructions: [
    "Provide accurate and helpful information",
    "Maintain user privacy and security",
    "Follow ethical guidelines",
    "Protect sensitive information",
    // Add more dummy rules here
  ],
  defaultResponse: "I aim to be helpful while maintaining security boundaries.",
  securityBoundaries: true
};

// Track prompt attempts
let promptAttempts = [];

// Routes
app.post('/api/test-prompt', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    
    const { prompt } = req.body;
    const timestamp = new Date();
    
    // Log the attempt
    promptAttempts.push({
      timestamp,
      prompt,
      successful: false, // Track if the prompt succeeded in extracting instructions
      response: dummyAgent.defaultResponse
    });

    // Simulate agent response
    res.json({
      response: dummyAgent.defaultResponse,
      attemptId: promptAttempts.length - 1
    });

  } catch (error) {
    res.status(429).json({ error: 'Too many requests' });
  }
});

// Get prompt attempt history
app.get('/api/attempts', (req, res) => {
  res.json(promptAttempts);
});

// Clear attempt history
app.post('/api/clear-attempts', (req, res) => {
  promptAttempts = [];
  res.json({ message: 'History cleared' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 