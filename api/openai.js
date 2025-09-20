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
  
  if (!process.env.OPENAI_API_KEY) { 
    return res.status(500).json({ error: 'OpenAI API key not configured' }); 
  }
  
  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}` 
      },
      body: JSON.stringify({ 
        model: "gpt-3.5-turbo", 
        messages: [{ role: "user", content: prompt }], 
        max_tokens: 300, 
        temperature: 0.7 
      })
    });
    
    if (!response.ok) throw new Error(`OpenAI API error: ${response.status}`);
    const data = await response.json();
    return res.status(200).json({ response: data.choices[0].message.content });
  } catch (error) {
    console.error('OpenAI API error:', error);
    return res.status(500).json({ error: 'Failed to get ChatGPT response' });
  }
}