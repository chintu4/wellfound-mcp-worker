# Wellfound Jobs MCP Server (Cloudflare Worker + Google OAuth 2.1)

Remote Model Context Protocol (MCP) JSON-RPC 2.0 server with **OAuth 2.1 (PKCE + Dynamic Client Registration)**, **Google Sign-In**, **Cloudflare KV token storage**, and **Account Connect / Disconnect** controls.

## Architecture & OAuth Flow
1. **MCP Client Discovery**: Exposes `/.well-known/oauth-protected-resource` (RFC 9728) and `/.well-known/oauth-authorization-server` (RFC 8414) plus `/register` (RFC 7591).
2. **Google Sign-In (`/authorize` → Google → `/callback`)**: When a user connects from Claude Desktop, Cursor, or MCP Inspector without a hardcoded token, the browser opens Google Sign-In, verifies the user's identity, stores the user connection in Cloudflare `OAUTH_KV`, and issues an OAuth 2.1 Bearer access + refresh token to the MCP client.
3. **Connect & Disconnect Account (`/account` & `disconnect_wellfound_account`)**:
   - Visit `/account` in your browser to link or rotate your Wellfound session cookie (`_wellfound`) and `X-CSRF-Token`, or disconnect your account.
   - Ask your AI assistant to run `disconnect_wellfound_account` (with optional `revoke_mcp_token: true`) to wipe stored credentials and revoke the active MCP OAuth token.

## Google Cloud OAuth Setup
1. Open [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials) and create an **OAuth 2.0 Client ID (Web application)**.
2. Add Authorized Redirect URI:
   `https://wellfound-mcp-worker.chintusharma00014.workers.dev/callback`
3. Set secrets in Cloudflare Workers:
   ```bash
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   npx wrangler secret put ALLOWED_EMAILS   # Optional comma-separated allowlist, e.g. chintusharma00014@gmail.com
   ```

## MCP Client Configuration (Zero-Secret OAuth Mode)
```json
{
  "mcpServers": {
    "wellfound": {
      "url": "https://wellfound-mcp-worker.chintusharma00014.workers.dev/mcp"
    }
  }
}
```
