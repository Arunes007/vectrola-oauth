const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Trust Railway's proxy (fixes X-Forwarded-For error)
app.set('trust proxy', 1);

// Parse JSON bodies
app.use(express.json());

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
}));

// Rate limiting (100 requests per 15 minutes per IP)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// =============================================================================
// In-memory storage for PKCE verifiers (short-lived, keyed by state)
// =============================================================================
const pendingAuth = new Map();

// Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of pendingAuth.entries()) {
    if (now - data.createdAt > 10 * 60 * 1000) { // 10 min expiry
      pendingAuth.delete(state);
    }
  }
}, 5 * 60 * 1000);

// =============================================================================
// Step 1: Plugin calls this to start auth flow (stores PKCE verifier)
// =============================================================================
app.post('/auth/start', (req, res) => {
  const { state, code_verifier } = req.body;

  if (!state || !code_verifier) {
    return res.status(400).json({ error: 'Missing state or code_verifier' });
  }

  // Store verifier for later token exchange
  pendingAuth.set(state, {
    code_verifier,
    createdAt: Date.now(),
  });

  console.log(`Auth started (state: ${state})`);
  res.json({ ok: true });
});

// =============================================================================
// Step 2: Google redirects here with auth code
// =============================================================================
app.get('/callback', (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.log(`OAuth error: ${error} - ${error_description}`);
    return res.render('callback', {
      success: false,
      error: error_description || error,
      code: null,
      state: null,
    });
  }

  if (!code) {
    console.log('No authorization code received');
    return res.render('callback', {
      success: false,
      error: 'No authorization code received',
      code: null,
      state: null,
    });
  }

  console.log(`Auth code received (state: ${state})`);
  res.render('callback', {
    success: true,
    code,
    state,
    error: null,
  });
});

// =============================================================================
// Step 3: Plugin calls this to exchange code for tokens (server-side)
// =============================================================================
app.post('/auth/token', async (req, res) => {
  const { code, state } = req.body;

  if (!code || !state) {
    return res.status(400).json({ error: 'Missing code or state' });
  }

  // Get stored verifier
  const authData = pendingAuth.get(state);
  if (!authData) {
    return res.status(400).json({ error: 'Invalid or expired state. Please try again.' });
  }

  const { code_verifier } = authData;

  // Clean up
  pendingAuth.delete(state);

  // Exchange code for tokens using client_secret (server-side only!)
  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        code_verifier,
        grant_type: 'authorization_code',
        redirect_uri: `${process.env.BASE_URL || 'https://vectrola-oauth.up.railway.app'}/callback`,
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('Token exchange error:', tokens);
      return res.status(400).json({ error: tokens.error_description || tokens.error });
    }

    console.log(`Token exchange successful (state: ${state})`);
    res.json({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
    });
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

// =============================================================================
// Step 4: Plugin calls this to refresh tokens
// =============================================================================
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'Missing refresh_token' });
  }

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token,
        grant_type: 'refresh_token',
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('Token refresh error:', tokens);
      return res.status(400).json({ error: tokens.error_description || tokens.error });
    }

    res.json({
      access_token: tokens.access_token,
      expires_in: tokens.expires_in,
    });
  } catch (err) {
    console.error('Token refresh failed:', err);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// Health check for Railway
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Root redirect to GitHub
app.get('/', (req, res) => {
  res.redirect('https://github.com/Arunes007/vectrola-sync');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vectrola OAuth server running on port ${PORT}`);
});
