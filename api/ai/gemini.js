import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

function verifyToken(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('No token provided');
    }
    
    const token = authHeader.substring(7);
    return jwt.verify(token, JWT_SECRET);
}

export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method not allowed' });
    }

    try {
        // Verify JWT token
        verifyToken(req);

        let body;
        if (typeof req.body === 'string') {
            body = JSON.parse(req.body);
        } else {
            body = req.body;
        }
        const { prompt, maxTokens = 300 } = body;

        if (!prompt) {
            return res.status(400).json({ success: false, error: 'Prompt is required' });
        }

        if (!GEMINI_API_KEY) {
            return res.status(200).json({
                success: true,
                response: "Hello! I'm Gemini. I'm currently in demo mode since no Google AI API key is configured. In a real deployment, I would use the Google AI API to provide creative and innovative responses to your questions."
            });
        }

        // Call Gemini API
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: prompt
                    }]
                }],
                generationConfig: {
                    maxOutputTokens: maxTokens,
                    temperature: 0.7
                }
            })
        });

        if (!response.ok) {
            throw new Error(`Gemini API error: ${response.status}`);
        }

        const data = await response.json();
        const aiResponse = data.candidates?.[0]?.content?.parts?.[0]?.text || 'Sorry, I could not generate a response.';

        res.status(200).json({
            success: true,
            response: aiResponse
        });

    } catch (error) {
        console.error('Gemini API error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }
        
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get response from Gemini' 
        });
    }
}
