require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const helmet = require('helmet');
const cors = require('cors');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const securityUpdates = require('./services/security-updates');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Setup WebSocket server (MCP)
const wss = new WebSocket.Server({ server });
global.wss = wss; // Make WSS available globally for broadcasts

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit payload size

// Rate limiting
const rateLimiter = new RateLimiterMemory({
  points: 10, // Number of points
  duration: 1, // Per second
});

// Initialize security updates service
securityUpdates.initialize().catch(error => {
  logger.error('Failed to initialize security updates service:', error);
});

// WebSocket connection handler (MCP)
wss.on('connection', (ws, req) => {
  logger.info('New client connected');

  // Implement WebSocket security
  const token = req.url.split('token=')[1];
  if (!token || !verifyToken(token)) {
    ws.close();
    return;
  }

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      // Rate limiting check
      try {
        await rateLimiter.consume(ws._socket.remoteAddress);
      } catch (error) {
        ws.send(JSON.stringify({ error: 'Too many requests' }));
        return;
      }

      // Handle different message types
      switch (data.type) {
        case 'SEARCH_SECURITY_DOCS':
          handleSecuritySearch(ws, data);
          break;
        case 'CODE_SCAN':
          handleCodeScan(ws, data);
          break;
        case 'SUBSCRIBE_UPDATES':
          handleSubscription(ws, data);
          break;
        case 'REQUEST_LATEST_DOCS':
          handleLatestDocsRequest(ws, data);
          break;
        default:
          ws.send(JSON.stringify({ error: 'Invalid message type' }));
      }
    } catch (error) {
      logger.error('Error processing message:', error);
      ws.send(JSON.stringify({ error: 'Internal server error' }));
    }
  });

  ws.on('close', () => {
    logger.info('Client disconnected');
  });
});

// Security documentation endpoints
app.get('/api/security/owasp', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    res.json(require('./data/owasp.json'));
  } catch (error) {
    res.status(429).json({ error: 'Too many requests' });
  }
});

app.get('/api/security/mitre', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    res.json(require('./data/mitre.json'));
  } catch (error) {
    res.status(429).json({ error: 'Too many requests' });
  }
});

app.get('/api/security/llm', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    res.json(require('./data/llm-security.json'));
  } catch (error) {
    res.status(429).json({ error: 'Too many requests' });
  }
});

app.post('/api/security/scan', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    const { code } = req.body;
    const vulnerabilities = await scanCodeForVulnerabilities(code);
    res.json(vulnerabilities);
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

// Helper functions
function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return false;
  }
}

async function handleSecuritySearch(ws, data) {
  // Implement AI-powered security documentation search
  const searchResults = await searchSecurityDocs(data.query);
  ws.send(JSON.stringify({
    type: 'SEARCH_RESULTS',
    data: searchResults
  }));
}

async function handleCodeScan(ws, data) {
  // Implement code scanning for security vulnerabilities
  const vulnerabilities = await scanCodeForVulnerabilities(data.code);
  ws.send(JSON.stringify({
    type: 'SCAN_RESULTS',
    data: vulnerabilities
  }));
}

function handleSubscription(ws, data) {
  // Store subscription preferences
  ws.subscriptions = ws.subscriptions || new Set();
  if (data.subscribe) {
    ws.subscriptions.add(data.source);
  } else {
    ws.subscriptions.delete(data.source);
  }
}

async function handleLatestDocsRequest(ws, data) {
  try {
    const source = data.source;
    const docs = require(`./data/${source}.json`);
    ws.send(JSON.stringify({
      type: 'LATEST_DOCS',
      source: source,
      data: docs
    }));
  } catch (error) {
    logger.error('Error sending latest docs:', error);
    ws.send(JSON.stringify({ error: 'Failed to fetch latest documentation' }));
  }
}

async function searchSecurityDocs(query) {
  // Implement AI-powered search across security documentation
  // This would integrate with OpenAI or similar for intelligent searching
  return [];
}

async function scanCodeForVulnerabilities(code) {
  // Implement code scanning logic
  // This would integrate with various security scanning tools
  return [];
}

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
}); 