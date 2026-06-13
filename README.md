# Vectrola OAuth Server

OAuth callback server for the [Vectrola Sync](https://github.com/Arunes007/vectrola-sync) Obsidian plugin.

## What This Does

This is a simple redirect server for Google OAuth. When users authenticate in the Obsidian plugin:

1. Plugin opens Google OAuth in browser
2. User signs in and grants permission
3. Google redirects to this server with an auth code
4. This server displays the code for the user to copy
5. User pastes the code back into Obsidian

## Why It's Needed

Obsidian plugins run in Electron and can't start a localhost server to receive OAuth callbacks. This hosted server acts as the redirect target.

## Security

- Uses PKCE (Proof Key for Code Exchange) - no client secrets in the plugin
- Rate limited to prevent abuse
- Helmet.js for security headers
- Auth codes expire in minutes
- No data is stored server-side

## Deployment

Deployed on [Railway](https://railway.app).

```bash
railway login
railway init
railway up
```

## Local Development

```bash
npm install
npm run dev
```

Visit http://localhost:3000/callback?code=test to test the UI.

## License

MIT
