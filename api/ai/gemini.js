// api/ai/gemini.js
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

    // Get Gemini API key from environment
    const geminiApiKey = process.env.GEMINI_API_KEY;
    if (!geminiApiKey) {
      console.error('GEMINI_API_KEY environment variable not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Get request data
    const { prompt, maxTokens = 300 } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // Prepare Gemini prompt with personality
    const geminiPrompt = `You are Google's Gemini AI. Respond as Gemini would - be creative, offer fresh perspectives, and think outside the box. Be innovative and dynamic.

${prompt}`;

    // Call Gemini API
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${geminiApiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: geminiPrompt
          }]
        }],
        generationConfig: {
          maxOutputTokens: maxTokens,
          temperature: 0.8,
          topK: 40,
          topP: 0.95
        }
      })
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('Gemini API error:', response.status, errorData);
      return res.status(500).json({ error: 'Failed to generate response' });
    }

    const data = await response.json();

    // Extract response text
    const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated';

    // Log usage (without sensitive data)
    console.log('Gemini API call completed:', {
      timestamp: new Date().toISOString(),
      candidates: data.candidates?.length || 0
    });

    res.status(200).json({
      success: true,
      response: generatedText,
      usage: {
        candidates: data.candidates?.length || 0
      }
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    console.error('Gemini API handler error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}