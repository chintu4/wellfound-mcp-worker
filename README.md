# Wellfound Jobs MCP Server (Cloudflare Worker)

Remote Model Context Protocol (MCP) JSON-RPC 2.0 server for searching, filtering, and inspecting startup jobs and companies on [Wellfound](https://wellfound.com/jobs), built for Cloudflare Workers.

## Features
- **MCP Endpoint Auth**: Protects `/mcp` (and `/`) via `Authorization: Bearer <MCP_AUTH_TOKEN>` or `X-API-Key: <MCP_AUTH_TOKEN>`.
- **Wellfound Session Auth**: Supports authenticated Wellfound GraphQL queries (`WELLFOUND_SESSION_COOKIE` + `WELLFOUND_CSRF_TOKEN`) with automatic public Apollo/Next SSR state fallback when session credentials are omitted or challenged.
- **Tools Included**:
  - `search_wellfound_jobs`: Filter by role slug, location slug, remote-only, job type, and page.
  - `get_wellfound_job_details`: Fetch full job description, compensation, equity, skills, and screening questions by job slug.
  - `get_wellfound_company`: Fetch startup profile, funding stage, total raised, team size, and open jobs by company slug.
  - `list_wellfound_applications`: Fetch your submitted applications (requires authenticated Wellfound session cookie).

## Setup & Secrets

Set secrets in Cloudflare Workers:

```bash
npx wrangler secret put MCP_AUTH_TOKEN
npx wrangler secret put WELLFOUND_SESSION_COOKIE   # Optional: _wellfound cookie from browser
npx wrangler secret put WELLFOUND_CSRF_TOKEN       # Optional: x-csrf-token meta tag value
```

## MCP Client Configuration

```json
{
  "mcpServers": {
    "wellfound": {
      "url": "https://wellfound-mcp-worker.<your-subdomain>.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```
