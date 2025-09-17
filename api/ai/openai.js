// api/ai/openai.js
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

    // Get OpenAI API key from environment
    const openaiApiKey = process.env.OPENAI_API_KEY;
    if (!openaiApiKey) {
      console.error('OPENAI_API_KEY environment variable not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Get request data
    const { prompt, maxTokens = 300 } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // Call OpenAI API
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-3.5-turbo',
        messages: [
          {
            role: 'system',
            content: 'You are ChatGPT, a helpful AI assistant. Respond as ChatGPT would - be analytical, helpful, and focus on practical solutions. Keep responses concise and conversational.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: maxTokens,
        temperature: 0.7
      })
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('OpenAI API error:', response.status, errorData);
      return res.status(500).json({ error: 'Failed to generate response' });
    }

    const data = await response.json();

    // Log usage (without sensitive data)
    console.log('OpenAI API call completed:', {
      timestamp: new Date().toISOString(),
      tokens: data.usage?.total_tokens || 'unknown'
    });

    res.status(200).json({
      success: true,
      response: data.choices[0].message.content,
      usage: data.usage
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    console.error('OpenAI API handler error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}