// api/ai/claude.js
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
    // Verify authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');

    if (!decoded.authenticated) {
      return res.status(401).json({ error: 'Invalid authentication' });
    }

    // Get Claude API key from environment
    const claudeApiKey = process.env.CLAUDE_API_KEY;
    if (!claudeApiKey) {
      console.error('CLAUDE_API_KEY environment variable not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Get request data
    const { prompt, maxTokens = 300 } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // Call Claude API
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': claudeApiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-3-sonnet-20240229',
        max_tokens: maxTokens,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('Claude API error:', response.status, errorData);
      return res.status(500).json({ error: 'Failed to generate response' });
    }

    const data = await response.json();

    // Log usage (without sensitive data)
    console.log('Claude API call completed:', {
      timestamp: new Date().toISOString(),
      tokens: data.usage?.output_tokens || 'unknown'
    });

    res.status(200).json({
      success: true,
      response: data.content[0].text,
      usage: data.usage
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    console.error('Claude API handler error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}