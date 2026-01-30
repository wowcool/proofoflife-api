import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { setupRoutes } from './routes.js';

const app = express();
const PORT = parseInt(process.env.PORT || '5000', 10);

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'proofoflife-api', timestamp: new Date().toISOString() });
});

// Setup all routes
setupRoutes(app);

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(\`[ProofOfLife API] Server running on port \${PORT}\`);
  console.log(\`[ProofOfLife API] Environment: \${process.env.NODE_ENV || 'development'}\`);
});
