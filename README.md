# Wellfound Jobs MCP Server (Cloudflare Worker — Read & Write)

Remote Model Context Protocol (MCP) JSON-RPC 2.0 server for searching, inspecting, bookmarking, messaging, and applying to startup jobs on [Wellfound](https://wellfound.com/jobs), deployed on Cloudflare Workers.

## Features
- **MCP Endpoint Auth**: Protects `/mcp` (and `/`) via `Authorization: Bearer <MCP_AUTH_TOKEN>` or `X-API-Key: <MCP_AUTH_TOKEN>`.
- **Read Tools**:
  - `search_wellfound_jobs`: Filter by role slug, location slug, remote-only, job type, and page.
  - `get_wellfound_job_details`: Fetch full job description, compensation, equity, skills, and screening questions.
  - `get_wellfound_company`: Fetch startup profile, funding stage, total raised, team size, and open jobs.
  - `list_wellfound_applications`: List your submitted applications (requires authenticated Wellfound session cookie).
- **Write Tools** (require `WELLFOUND_SESSION_COOKIE` + `WELLFOUND_CSRF_TOKEN`):
  - `apply_to_wellfound_job`: Submit a job application with a personalized recruiter pitch (`note`), screening question answers, and `dry_run` preview mode.
  - `save_wellfound_job`: Bookmark or unsave a job listing.
  - `send_wellfound_message`: Send a follow-up message inside an existing recruiter/application thread.
  - `update_wellfound_profile_headline`: Update your candidate headline/bio and job-search availability status (`ACTIVE`, `OPEN`, `CLOSED`).

## Setup & Secrets

```bash
npx wrangler secret put MCP_AUTH_TOKEN
npx wrangler secret put WELLFOUND_SESSION_COOKIE   # _wellfound cookie from browser DevTools
npx wrangler secret put WELLFOUND_CSRF_TOKEN       # x-csrf-token header/meta tag from browser DevTools
```

## MCP Client Configuration

```json
{
  "mcpServers": {
    "wellfound": {
      "url": "https://wellfound-mcp-worker.chintusharma00014.workers.dev/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```
