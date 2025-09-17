// api/auth/login.js
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    // Get master password from environment
    const masterPassword = process.env.MASTER_PASSWORD;
    if (!masterPassword) {
      console.error('MASTER_PASSWORD environment variable not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // In production, you might want to hash the master password
    // For now, we'll do a direct comparison
    if (password !== masterPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        authenticated: true,
        timestamp: Date.now()
      },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '24h' }
    );

    // Log successful authentication (without sensitive data)
    console.log('Successful authentication at:', new Date().toISOString());

    res.status(200).json({
      success: true,
      token,
      message: 'Authentication successful'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}