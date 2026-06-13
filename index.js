const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Trust Railway's proxy (fixes X-Forwarded-For error)
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Needed for inline copyCode()
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

// OAuth callback endpoint
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
