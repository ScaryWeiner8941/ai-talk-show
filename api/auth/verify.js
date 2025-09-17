// api/auth/verify.js
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { token } = req.body;
    const authHeader = req.headers.authorization;

    // Get token from body or Authorization header
    const tokenToVerify = token || (authHeader && authHeader.split(' ')[1]);

    if (!tokenToVerify) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Verify JWT token
    const decoded = jwt.verify(tokenToVerify, process.env.JWT_SECRET || 'fallback-secret-key');

    // Check if token is still valid (additional validation)
    if (!decoded.authenticated) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    res.status(200).json({
      success: true,
      valid: true,
      message: 'Token is valid'
    });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }

    console.error('Token verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}