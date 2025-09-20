import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const MASTER_PASSWORD_HASH = process.env.MASTER_PASSWORD_HASH || '$2a$10$3xVQl2dLg.7I9UOEEKx.qeHOqIGM8OMfQ7Z5KQ.xN.nVlEf9D.C6W';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

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
        // Simple password validation for demo
        const password = req.body?.password;

        if (!password) {
            return res.status(400).json({ success: false, error: 'Password is required' });
        }

        // For demo purposes, just check the plain text password
        if (password !== 'ConvoPlay2025!') {
            return res.status(401).json({ success: false, error: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { authenticated: true, timestamp: Date.now() },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({
            success: true,
            token,
            message: 'Authentication successful'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
}