# Meta Webhook & Callback Control Center

Node.js/Express app for receiving Meta Platform webhooks, completing Meta's webhook verification handshake, validating `X-Hub-Signature-256`, capturing generic callbacks, and inspecting events in a password-protected dashboard.

## Endpoints

- `GET /health` — Railway health check.
- `GET /webhook` — Meta subscription verification (`hub.mode`, `hub.verify_token`, `hub.challenge`).
- `POST /webhook` — Meta notifications. Returns `200` quickly after saving the event; invalid signatures return `401` when `META_APP_SECRET` is configured.
- `ALL /callback` — Generic callback capture endpoint; responds with JSON containing the stored `event_id`.
- `POST /facebook/deauthorize` — Facebook Login deauthorization callback (`signed_request`).
- `POST /facebook/data-deletion` — Facebook Login data deletion callback (`signed_request`).
- `GET /auth/facebook` — starts Facebook Login OAuth.
- `GET /auth/facebook/callback` — exchanges the login code for a short-lived token, then for a long-lived user token.
- `GET /api/token/status` and `POST /api/token/reveal` — password-protected token status/reveal endpoints.
- `GET /api/events` and `GET /api/stats` — dashboard APIs, protected by `x-dashboard-password`.

## Deploy to Railway (iPhone-friendly)

1. Create a GitHub repository and upload all files/folders from this project.
2. In Railway, choose **New Project → Deploy from GitHub Repo** and select the repository.
3. In the Railway service **Variables**, add:
   - `META_VERIFY_TOKEN`: a long random string you create. It must exactly match the token entered in Meta's webhook configuration.
   - `META_APP_ID`: your Meta App ID.
   - `META_APP_SECRET`: your Meta App Secret (server-side only).
   - `TOKEN_ENCRYPTION_KEY`: a random 32-byte key as exactly 64 hex characters. Generate one with any trusted random generator; keep it private and never change it after tokens have been saved unless you first re-encrypt them.
   - `META_GRAPH_VERSION`: a Graph API version supported by your Meta app (default in sample: `v24.0`).
   - `META_LOGIN_SCOPES`: comma-separated permissions your app needs and is approved to request (sample defaults are only a starting point).
   - `DASHBOARD_PASSWORD`: a strong password for the dashboard.
   - `DB_PATH`: `/data/events.sqlite`
4. Add a Railway **Volume** to the service and mount it at `/data`. Without a persistent volume, SQLite data may be lost when the container is replaced.
5. Generate a Railway public domain. Your Meta callback URL is `https://YOUR-DOMAIN/webhook`. Your generic callback URL is `https://YOUR-DOMAIN/callback`.
6. In Meta Developer Dashboard → Facebook Login settings, add this exact Valid OAuth Redirect URI: `https://YOUR-DOMAIN/auth/facebook/callback`. Ensure the Facebook Login product is configured and your app has the required permissions. The dashboard's **Connect Facebook** button starts the OAuth flow; Meta returns an authorization code, the server obtains a short-lived user token, then exchanges it for a long-lived user token (normally about 60 days). The long-lived token is encrypted in SQLite. It can be revealed only after dashboard password authentication.
7. Open the Meta Developer Dashboard → your app → Webhooks. Enter the callback URL and exact verify token, then subscribe to the required product/object and fields. Meta setup differs by product (Facebook Login, Instagram, WhatsApp, Pages, etc.).
8. Open your Railway domain to use the event dashboard. Enter `DASHBOARD_PASSWORD`.

## Local run

Requires Node.js 20+.

```bash
npm install
cp .env.example .env
# Fill in the values in .env
npm start
```

## Test Meta verification

Replace values and URL:

```bash
curl "https://YOUR-DOMAIN/webhook?hub.mode=subscribe&hub.verify_token=YOUR_TOKEN&hub.challenge=12345"
```

The response should be the plain text `12345`.

## Test generic callback

```bash
curl -X POST "https://YOUR-DOMAIN/callback" \
  -H "Content-Type: application/json" \
  -H "X-Event-Type: test.event" \
  -d '{"hello":"world","status":"success"}'
```

## Test Meta POST signature locally

Meta computes `X-Hub-Signature-256` as `sha256=` plus an HMAC-SHA256 of the exact raw request body using your App Secret. The app preserves raw request bytes for this check. Do not put the App Secret in frontend code.

## OAuth token notes

- The OAuth redirect URL must match exactly in Meta's Valid OAuth Redirect URIs and in the deployed Railway domain. If you change the domain, update Meta settings.
- A long-lived user token is usually valid for around 60 days, not forever. It may be invalidated earlier if the user revokes access, changes security settings, or permissions change. Reconnect before expiry; an expired token cannot be exchanged.
- This flow produces a long-lived **user** token. For Facebook Pages, use the user's granted permissions to fetch Page access tokens (for example via `/me/accounts`). Instagram API access and permissions depend on the Instagram account/API setup; Instagram Login has a distinct token flow and is not interchangeable with Facebook Login.
- Never expose the App Secret or encryption key in frontend code, GitHub, screenshots, or chat. Back up the encryption key securely; losing it makes stored tokens unreadable.

## Important production notes

- Configure `META_APP_SECRET`; otherwise events are accepted but marked as signature **not verified**. For production, keep it configured.
- The generic `/callback` route is a capture endpoint, not a universal provider signature verifier. Add the specific provider's signature/authentication scheme before trusting callbacks for payments, account changes, or other sensitive actions.
- Subscribe only to the Meta products and webhook fields your app actually uses.
- This starter stores event payloads. Review data retention and privacy requirements before using it with personal data. Consider redaction and retention limits.
- The server acknowledges Meta quickly. If you need reliable heavy processing, enqueue work and process it in a separate worker rather than delaying the webhook response.


## Product-specific setup notes

- Instagram Graph API: the webhook object and subscribed fields depend on the Instagram API setup and account type. Subscribe only to fields enabled for your app and complete the required app review/permissions.
- Facebook Pages: use the Page-related webhook object and fields supported for the Page permissions granted to your app. For Page-scoped subscriptions, complete the app's Page subscription flow as required by Meta.
- Facebook Login: the deauthorization and data-deletion endpoints capture Meta's signed request and verify it with `META_APP_SECRET` when configured. This starter records the request and returns a confirmation code/status URL. It does **not** automatically delete user data from your own database; implement that before production and provide a public status URL via `DATA_DELETION_STATUS_URL` and, optionally, `FACEBOOK_DEAUTH_STATUS_URL`.
- These products do not all use identical callback formats. This app deliberately keeps the Graph API webhook receiver and Login-specific callbacks separate.
