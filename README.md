# CPA P-Code Starter

Starter project for a server-issued, one-time CPA proof code. Frontend is plain HTML/JavaScript; backend is Node.js + Express; storage is SQLite.

## Important limitation

A browser page cannot reliably prove that an Android app was installed or opened. A download click, timer, JavaScript event, or user-submitted screenshot is not authoritative proof. For real campaigns, connect a mobile measurement partner (MMP) or the advertiser's trusted server-to-server postback. The provider must send a signed `install_verified` event containing the session ID you passed through its supported attribution/sub-ID mechanism.

The included demo endpoint deliberately **simulates** a provider callback. It is for local testing only and does not prove a real install.

## Requirements

- Node.js 20+
- npm

## Run locally

1. Copy `.env.example` to `.env`.
2. Replace both secrets with long random values. Example generation:
   - macOS/Linux: `openssl rand -hex 32`
   - Node: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
3. Install and start:

   ```bash
   npm install
   npm start
   ```

4. Open `http://localhost:3000`.
5. For a full local simulation, in another terminal run:

   ```bash
   npm run demo
   ```

   The script creates a session, simulates a trusted callback using the local-only demo route, and prints the P-Code.

## API

### `POST /api/start`

Creates a one-hour session.

Response:
```json
{ "success": true, "session_id": "..." }
```

### `POST /api/provider/install-callback`

Provider webhook. Send raw JSON and header `x-cpa-signature`, the lowercase hex HMAC-SHA256 of the exact raw request body using `POSTBACK_SECRET`.

Expected JSON:
```json
{
  "event_id": "provider-unique-event-id",
  "session_id": "48-character-session-id",
  "event_type": "install_verified"
}
```

The provider integration must map its verified install event to the session ID using a supported attribution parameter. Confirm the provider's signature format and event semantics before connecting it; adapt this endpoint to the provider's official documentation.

### `GET /api/code/:sessionId`

Returns the P-Code only after a verified provider callback. Code expires after 30 minutes.

### `POST /api/redeem`

Server-to-server redemption. Requires header `x-api-key: REDEEM_API_KEY` and body:
```json
{ "code": "CPA-0123456789" }
```

A successful redemption atomically marks the code as used. Keep the API key on your backend only, never in frontend JavaScript.

## Before production

- Set `ENABLE_DEMO_ENDPOINT=false`.
- Use HTTPS.
- Use a production database (PostgreSQL recommended for multiple app instances).
- Keep secrets in your hosting provider's secret manager; never commit `.env`.
- Add provider-specific webhook signature verification, timestamp/replay protection, and event-field validation.
- Ensure provider callback delivery is retried safely and event IDs are idempotent.
- Authenticate `/api/redeem` from your CPA platform backend and restrict network access where possible.
- Add CSRF protection if you later use cookie-based sessions.
- Add retention limits, privacy notice, and only collect data needed for fraud prevention.
- Rate limiting by IP is only one signal; avoid treating IP/device fingerprints as definitive proof of fraud.
- Do not award a completed-install reward based only on a download click or client-side JavaScript.
