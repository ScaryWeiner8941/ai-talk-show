require('dotenv').config({ path: '.env.local' });
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const pino = require('pino');

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Analytics logging
const fs = require('fs');
const path = require('path');

const ANALYTICS_FILE = path.join(__dirname, 'logs', 'events.jsonl');
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB

// Ensure logs directory exists
try {
  fs.mkdirSync(path.dirname(ANALYTICS_FILE), { recursive: true });
} catch (err) {
  logger.error('Failed to create logs directory:', err);
}

function logEvent(event) {
  const logEntry = {
    ...event,
    timestamp: new Date().toISOString(),
  };

  logEntry.route = logEntry.route ?? null;
  logEntry.vendor = logEntry.vendor ?? null;
  logEntry.duration = typeof logEntry.duration === 'number' ? logEntry.duration : null;
  if (typeof logEntry.success !== 'boolean') {
    logEntry.success = logEntry.success ?? null;
  }

  const logLine = JSON.stringify(logEntry) + '\n';

  // Rotate log if too large
  try {
    const stats = fs.statSync(ANALYTICS_FILE);
    if (stats.size > MAX_LOG_SIZE) {
      const backup = `${ANALYTICS_FILE}.${Date.now()}`;
      fs.renameSync(ANALYTICS_FILE, backup);
    }
  } catch (err) {
    // File doesn't exist yet, that's fine
  }

  try {
    fs.appendFileSync(ANALYTICS_FILE, logLine);
  } catch (err) {
    logger.error('Failed to write to analytics log:', err);
  }
}

const app = express();
const port = process.env.PORT || 3000;

// Trust proxy for rate limiting behind load balancers
app.set('trust proxy', 1);

// Validate critical environment variables
const jwtSecret = process.env.JWT_SECRET || '';
if (!jwtSecret) {
  logger.error('JWT_SECRET environment variable is required for security');
  process.exit(1);
}
if (Buffer.byteLength(jwtSecret, 'utf8') < 32) {
  logger.error('JWT_SECRET must be at least 32 bytes for adequate entropy');
  process.exit(1);
}

if (!process.env.MASTER_PASSWORD && !process.env.APP_PASSWORD) {
  logger.error('MASTER_PASSWORD or APP_PASSWORD environment variable is required');
  process.exit(1);
}

const DEFAULT_REQUIRED_PROVIDERS = ['claude', 'openai', 'gemini'];
const allowedProviderNames = new Set(DEFAULT_REQUIRED_PROVIDERS);
const requiredProvidersList = (process.env.REQUIRED_PROVIDERS || DEFAULT_REQUIRED_PROVIDERS.join(','))
  .split(',')
  .map((provider) => provider.trim().toLowerCase())
  .filter(Boolean);

const unknownProviders = requiredProvidersList.filter((provider) => !allowedProviderNames.has(provider));
if (unknownProviders.length) {
  logger.warn({ providers: unknownProviders }, 'REQUIRED_PROVIDERS contains unknown provider identifiers');
}

const requiredProviderSet = new Set(
  requiredProvidersList.filter((provider) => allowedProviderNames.has(provider))
);

const hasClaudeKey = Boolean(process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY);
const hasOpenAIKey = Boolean(process.env.OPENAI_API_KEY);
const hasGeminiKey = Boolean(process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY);

const missingRequiredProviders = [];
if (requiredProviderSet.has('claude') && !hasClaudeKey) {
  missingRequiredProviders.push('Anthropic');
}
if (requiredProviderSet.has('openai') && !hasOpenAIKey) {
  missingRequiredProviders.push('OpenAI');
}
if (requiredProviderSet.has('gemini') && !hasGeminiKey) {
  missingRequiredProviders.push('Google Gemini');
}

if (missingRequiredProviders.length) {
  logger.error({ providers: missingRequiredProviders }, 'Required AI provider API keys are missing. Set them before starting the server.');
  process.exit(1);
}

const providerAvailability = {
  claude: requiredProviderSet.has('claude') && hasClaudeKey,
  openai: requiredProviderSet.has('openai') && hasOpenAIKey,
  gemini: requiredProviderSet.has('gemini') && hasGeminiKey,
};

if (requiredProviderSet.size === 0) {
  logger.warn('REQUIRED_PROVIDERS is empty. All AI providers are disabled.');
}

const disabledProviders = Object.entries(providerAvailability)
  .filter(([, enabled]) => !enabled)
  .map(([name]) => name);
if (disabledProviders.length) {
  logger.warn({ providers: disabledProviders }, 'Some AI providers are disabled via REQUIRED_PROVIDERS');
}

const providerKeys = {
  claude: hasClaudeKey ? (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY) : null,
  openai: hasOpenAIKey ? process.env.OPENAI_API_KEY : null,
  gemini: hasGeminiKey ? (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY) : null,
};

const PROVIDER_AVAILABILITY = Object.freeze({ ...providerAvailability });
const PROVIDER_KEYS = Object.freeze({ ...providerKeys });

if (process.env.ALLOWED_ORIGINS) {
  const origins = process.env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean);
  const invalidOrigins = origins.filter((origin) => {
    try {
      const parsed = new URL(origin);
      return !parsed.protocol.startsWith('http');
    } catch (err) {
      return true;
    }
  });
  if (invalidOrigins.length) {
    logger.error({ invalidOrigins }, 'ALLOWED_ORIGINS contains invalid URLs');
    process.exit(1);
  }
}

if (!process.env.ANTHROPIC_MODEL) {
  logger.warn('ANTHROPIC_MODEL not set. Defaulting to claude-3-sonnet-20240229.');
}
if (!process.env.LOG_LEVEL) {
  logger.warn('LOG_LEVEL not set. Defaulting to info.');
}

// Security and middleware
app.use(helmet());
// Restrict CORS to prevent abuse
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
  : ['http://localhost:3000', 'https://localhost:3000'];
const allowedOriginsSet = new Set(allowedOrigins);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOriginsSet.has(origin)) {
    return next();
  }
  logger.warn({ origin, path: req.originalUrl }, 'CORS origin denied');
  return res.status(403).json({ error: 'Origin not allowed', code: 'CORS_DENIED' });
});

app.use(cors({ 
  origin: function (origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    return callback(null, allowedOriginsSet.has(origin));
  },
  methods: ["POST", "GET"], 
  allowedHeaders: ["content-type", "authorization"],
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

// Request logging
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    logger.info({
      method: req.method,
      path: req.originalUrl || req.url,
      status: res.statusCode,
      duration: Number(durationMs.toFixed(2))
    }, 'request');
  });
  next();
});
app.use(express.static('public'));

// Rate limiting for API routes
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    logEvent({ route: '/api/auth', vendor: 'auth', success: false, duration: 0, error: 'Too many authentication attempts', ip });
    res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
  }
});

// Handle known errors (e.g., body too large)
app.use('/api', (err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    logEvent({ route: req.originalUrl || req.url, vendor: 'api', success: false, duration: 0, error: 'Payload too large' });
    return res.status(413).json({ error: 'Request payload is too large (1MB limit).' });
  }
  return next(err);
});

// Daily usage tracking (cookie-based, in-memory)
const usageMap = new Map();
const DAILY_LIMIT = 100;

const authFailureMap = new Map();
const AUTH_FAILURE_WINDOW_MS = 15 * 60 * 1000;
const AUTH_FAILURE_THRESHOLD = 5;
const AUTH_BLOCK_DURATION_MS = 30 * 60 * 1000;
const AUTH_FAILURE_TTL_MS = 24 * 60 * 60 * 1000;
const LOG_USAGE_METRICS = process.env.LOG_USAGE_METRICS === 'true';

// Clean up old usage entries periodically to prevent memory leaks
setInterval(() => {
  const today = new Date().toDateString();
  for (const [key, value] of usageMap.entries()) {
    if (value.date !== today) {
      usageMap.delete(key);
    }
  }

  const now = Date.now();
  for (const [ip, record] of authFailureMap.entries()) {
    const lastActivity = record.lastAttempt || record.windowStart || record.blockedUntil || 0;
    const ttlExpired = lastActivity && (now - lastActivity > AUTH_FAILURE_TTL_MS);
    const blockExpired = record.blockedUntil && record.blockedUntil <= now;
    if (ttlExpired || (blockExpired && (!record.windowStart || now - record.windowStart > AUTH_FAILURE_WINDOW_MS))) {
      authFailureMap.delete(ip);
    }
  }

  if (LOG_USAGE_METRICS) {
    const memoryUsage = process.memoryUsage();
    logger.info({
      usageEntries: usageMap.size,
      authFailureEntries: authFailureMap.size,
      memoryRSS: memoryUsage.rss,
      memoryHeapUsed: memoryUsage.heapUsed
    }, 'usage cache metrics');
  }
}, 60 * 60 * 1000); // Clean up every hour

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [name, ...rest] = part.trim().split('=');
    if (!name) return acc;
    acc[name] = rest.join('=');
    return acc;
  }, {});
}

function attachUsageId(req, res) {
  const cookies = parseCookies(req);
  let usageId = cookies.usage_id;
  if (!usageId) {
    const generated = typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString('hex');
    usageId = generated;
    const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.secure;
    const secureFlag = isHttps ? '; Secure' : '';
    const cookieValue = 'usage_id=' + usageId + '; Path=/; HttpOnly; SameSite=Strict' + secureFlag + '; Max-Age=86400';
    const existing = res.getHeader('Set-Cookie');
    if (!existing) {
      res.setHeader('Set-Cookie', cookieValue);
    } else if (Array.isArray(existing)) {
      res.setHeader('Set-Cookie', [...existing, cookieValue]);
    } else {
      res.setHeader('Set-Cookie', [existing, cookieValue]);
    }
  }
  return usageId;
}

function dailyUsageCheck(req, res, next) {
  const usageId = attachUsageId(req, res);
  const today = new Date().toDateString();
  
  // Also track by IP as fallback to prevent cookie bypass
  const clientIP = req.ip || req.connection?.remoteAddress || "unknown";
  const combinedKey = `${usageId}:${clientIP}`;

  let usage = usageMap.get(combinedKey);
  if (!usage || usage.date !== today) {
    usage = { count: 0, date: today };
    usageMap.set(combinedKey, usage);
  }

  if (usage.count >= DAILY_LIMIT) {
    const resetAt = new Date();
    resetAt.setHours(24, 0, 0, 0);
    return res.status(429).json({
      error: 'Daily usage limit exceeded',
      limit: DAILY_LIMIT,
      resetAt: resetAt.toISOString()
    });
  }

  usage.count += 1;
  next();
}

app.use('/api', dailyUsageCheck);

// auth -> returns JWT if password matches
app.post('/api/auth', authLimiter, (req, res) => {
  const start = Date.now();
  const { password } = req.body || {};
  const master = process.env.APP_PASSWORD || process.env.MASTER_PASSWORD || '';
  const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';

  const now = Date.now();
  const existing = authFailureMap.get(clientIP);
  if (existing && existing.blockedUntil && existing.blockedUntil > now) {
    existing.lastAttempt = now;
    authFailureMap.set(clientIP, existing);
    logEvent({ route: '/api/auth', vendor: 'auth', success: false, duration: Date.now() - start, error: 'IP temporarily blocked', ip: clientIP });
    return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
  }
  if (existing && existing.blockedUntil && existing.blockedUntil <= now) {
    authFailureMap.delete(clientIP);
  }

  if (typeof password !== 'string' || !password) {
    logEvent({ route: '/api/auth', vendor: 'auth', success: false, duration: Date.now() - start, error: 'Password required', ip: clientIP });
    return res.status(400).json({ error: 'Password is required' });
  }

  if (password !== master) {
    const record = authFailureMap.get(clientIP) || { count: 0, windowStart: now, blockedUntil: 0, lastAttempt: 0 };
    if (!record.windowStart || now - record.windowStart > AUTH_FAILURE_WINDOW_MS) {
      record.count = 0;
      record.windowStart = now;
    }
    record.count += 1;
    record.lastAttempt = now;
    if (record.count >= AUTH_FAILURE_THRESHOLD) {
      record.blockedUntil = now + AUTH_BLOCK_DURATION_MS;
      record.count = 0;
      record.windowStart = now;
    }
    authFailureMap.set(clientIP, record);

    logEvent({ 
      route: '/api/auth', 
      vendor: 'auth', 
      success: false, 
      duration: Date.now() - start,
      error: 'Invalid password',
      ip: clientIP
    });
    return res.status(401).json({ error: 'Invalid password' });
  }

  authFailureMap.delete(clientIP);
  const token = jwt.sign({}, process.env.JWT_SECRET, { expiresIn: '1h' });

  logEvent({ 
    route: '/api/auth', 
    vendor: 'auth', 
    success: true, 
    duration: Date.now() - start,
    ip: clientIP 
  });

  res.json({ token });
});

// protect downstream APIs
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  try { jwt.verify(tok, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Unauthorized' }); }
}

// Claude API
app.post('/api/claude', requireAuth, async (req, res) => {
  const start = Date.now();
  const { prompt } = req.body;
  
  logEvent({ route: '/api/claude', vendor: 'anthropic', success: null, duration: 0, event: 'api_call_start' });

  if (!PROVIDER_AVAILABILITY.claude) {
    const duration = Date.now() - start;
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: false, duration, error: 'Provider disabled' });
    return res.status(503).json({ error: 'Claude provider disabled', code: 'PROVIDER_DISABLED' });
  }

  if (typeof prompt !== 'string' || !prompt.trim()) {
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: false, duration: Date.now() - start, error: 'Invalid prompt' });
    return res.status(400).json({ error: 'Prompt must be a non-empty string' });
  }

  if (prompt.length > 2000) {
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: false, duration: Date.now() - start, error: 'Prompt too long' });
    return res.status(413).json({ error: 'Prompt exceeds 2000 character limit' });
  }

  const anthropicKey = PROVIDER_KEYS.claude;
  if (!anthropicKey) {
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: false, duration: Date.now() - start, error: 'Provider unavailable' });
    return res.status(503).json({ error: 'Claude provider unavailable', code: 'PROVIDER_UNAVAILABLE' });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "x-api-key": anthropicKey, 
        "anthropic-version": "2023-06-01" 
      },
      body: JSON.stringify({ 
        model: process.env.ANTHROPIC_MODEL || "claude-3-sonnet-20240229", 
        max_tokens: 300, 
        messages: [{ role: "user", content: prompt }] 
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    const duration = Date.now() - start;
    
    if (!response.ok) throw new Error(`Claude API error: ${response.status}`);
    const data = await response.json();
    
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: true, duration });
    res.json({ response: data.content[0].text });
  } catch (error) {
    logEvent({ route: '/api/claude', vendor: 'anthropic', success: false, duration: Date.now() - start, error: error.message });
    logger.error('Claude API error:', error);
    res.status(500).json({ error: 'Failed to get Claude response' });
  }
});

// OpenAI API
app.post('/api/openai', requireAuth, async (req, res) => {
  const start = Date.now();
  const { prompt } = req.body;
  
  logEvent({ route: '/api/openai', vendor: 'openai', success: null, duration: 0, event: 'api_call_start' });

  if (!PROVIDER_AVAILABILITY.openai) {
    const duration = Date.now() - start;
    logEvent({ route: '/api/openai', vendor: 'openai', success: false, duration, error: 'Provider disabled' });
    return res.status(503).json({ error: 'OpenAI provider disabled', code: 'PROVIDER_DISABLED' });
  }

  if (typeof prompt !== 'string' || !prompt.trim()) {
    logEvent({ route: '/api/openai', vendor: 'openai', success: false, duration: Date.now() - start, error: 'Invalid prompt' });
    return res.status(400).json({ error: 'Prompt must be a non-empty string' });
  }

  if (prompt.length > 2000) {
    logEvent({ route: '/api/openai', vendor: 'openai', success: false, duration: Date.now() - start, error: 'Prompt too long' });
    return res.status(413).json({ error: 'Prompt exceeds 2000 character limit' });
  }

  const openAIKey = PROVIDER_KEYS.openai;
  if (!openAIKey) {
    logEvent({ route: '/api/openai', vendor: 'openai', success: false, duration: Date.now() - start, error: 'Provider unavailable' });
    return res.status(503).json({ error: 'OpenAI provider unavailable', code: 'PROVIDER_UNAVAILABLE' });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Authorization": `Bearer ${openAIKey}` 
      },
      body: JSON.stringify({ 
        model: "gpt-3.5-turbo", 
        messages: [{ role: "user", content: prompt }], 
        max_tokens: 300, 
        temperature: 0.7 
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    const duration = Date.now() - start;
    
    if (!response.ok) throw new Error(`OpenAI API error: ${response.status}`);
    const data = await response.json();
    
    logEvent({ route: '/api/openai', vendor: 'openai', success: true, duration });
    res.json({ response: data.choices[0].message.content });
  } catch (error) {
    logEvent({ route: '/api/openai', vendor: 'openai', success: false, duration: Date.now() - start, error: error.message });
    logger.error('OpenAI API error:', error);
    res.status(500).json({ error: 'Failed to get ChatGPT response' });
  }
});

// Gemini API
app.post('/api/gemini', requireAuth, async (req, res) => {
  const start = Date.now();
  const { prompt } = req.body;
  
  logEvent({ route: '/api/gemini', vendor: 'google', success: null, duration: 0, event: 'api_call_start' });

  if (!PROVIDER_AVAILABILITY.gemini) {
    const duration = Date.now() - start;
    logEvent({ route: '/api/gemini', vendor: 'google', success: false, duration, error: 'Provider disabled' });
    return res.status(503).json({ error: 'Gemini provider disabled', code: 'PROVIDER_DISABLED' });
  }

  if (typeof prompt !== 'string' || !prompt.trim()) {
    logEvent({ route: '/api/gemini', vendor: 'google', success: false, duration: Date.now() - start, error: 'Invalid prompt' });
    return res.status(400).json({ error: 'Prompt must be a non-empty string' });
  }

  if (prompt.length > 2000) {
    logEvent({ route: '/api/gemini', vendor: 'google', success: false, duration: Date.now() - start, error: 'Prompt too long' });
    return res.status(413).json({ error: 'Prompt exceeds 2000 character limit' });
  }

  const googleKey = PROVIDER_KEYS.gemini;
  if (!googleKey) {
    logEvent({ route: '/api/gemini', vendor: 'google', success: false, duration: Date.now() - start, error: 'Provider unavailable' });
    return res.status(503).json({ error: 'Gemini provider unavailable', code: 'PROVIDER_UNAVAILABLE' });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${googleKey}`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        contents: [{
          parts: [{ text: prompt }]
        }],
        generationConfig: {
          maxOutputTokens: 300,
          temperature: 0.7
        }
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    const duration = Date.now() - start;
    
    if (!response.ok) throw new Error(`Gemini API error: ${response.status}`);
    const data = await response.json();
    
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || "I couldn't generate a response.";
    
    logEvent({ route: '/api/gemini', vendor: 'google', success: true, duration });
    res.json({ response: responseText });
  } catch (error) {
    logEvent({ route: '/api/gemini', vendor: 'google', success: false, duration: Date.now() - start, error: error.message });
    logger.error('Gemini API error:', error);
    res.status(500).json({ error: 'Failed to get Gemini response' });
  }
});

// Health check endpoint
app.get('/healthz', (req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

const server = app.listen(port, () => {
  logger.info(`🚀 AI Talk Show server running on port ${port}`);
});

let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;
  logger.info({ signal }, 'Received shutdown signal, commencing graceful shutdown');

  const shutdownTimer = setTimeout(() => {
    logger.error('Graceful shutdown timed out, forcing exit');
    try { logger.flush?.(); } catch (err) { logger.error('Failed to flush logger during forced exit', err); }
    process.exit(1);
  }, 10000);
  shutdownTimer.unref();

  server.close((err) => {
    if (err) {
      logger.error({ err }, 'Error while closing HTTP server');
    } else {
      logger.info('HTTP server closed gracefully');
    }
    clearTimeout(shutdownTimer);
    try { logger.flush?.(); } catch (flushErr) {
      logger.error({ err: flushErr }, 'Failed to flush logger during shutdown');
    }
    process.exit(err ? 1 : 0);
  });
}

['SIGINT', 'SIGTERM'].forEach((signal) => {
  process.on(signal, () => gracefulShutdown(signal));
});
