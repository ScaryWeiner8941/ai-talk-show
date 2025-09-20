import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

function verifyToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('No token provided');
  }
  
  const token = authHeader.substring(7);
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    throw new Error('Invalid token');
  }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.status(200).end(); return; }
  if (req.method !== 'POST') { return res.status(405).json({ error: 'Method not allowed' }); }
  
  try {
    verifyToken(req);
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { prompt } = req.body;
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }
  
  if (!process.env.CLAUDE_API_KEY) { 
    return res.status(500).json({ error: 'Claude API key not configured' }); 
  }
  
  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "x-api-key": process.env.CLAUDE_API_KEY, 
        "anthropic-version": "2023-06-01" 
      },
      body: JSON.stringify({ 
        model: "claude-3-sonnet-20240229", 
        max_tokens: 300, 
        messages: [{ role: "user", content: prompt }] 
      })
    });
    
    if (!response.ok) throw new Error(`Claude API error: ${response.status}`);
    const data = await response.json();
    return res.status(200).json({ response: data.content[0].text });
  } catch (error) {
    console.error('Claude API error:', error);
    return res.status(500).json({ error: 'Failed to get Claude response' });
  }
}