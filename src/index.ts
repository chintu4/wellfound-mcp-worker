// Wellfound Jobs Cloudflare Worker MCP Server with Google OAuth 2.1 + Account Connect/Disconnect
// Implements:
//   - RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource)
//   - RFC 8414 Authorization Server Metadata (/.well-known/oauth-authorization-server)
//   - RFC 7591 Dynamic Client Registration (/register)
//   - OAuth 2.1 PKCE Authorization Code Flow (/authorize -> Google OAuth / Local Consent -> /callback -> /token)
//   - Token Revocation (/revoke) & Account Dashboard (/account) to connect/disconnect Wellfound session & revoke MCP access
//   - MCP JSON-RPC 2.0 Streamable HTTP (/mcp) + disconnect_wellfound_account tool

export interface Env {
  OAUTH_KV: KVNamespace;
  WELLFOUND_BASE_URL?: string;
  MCP_AUTH_TOKEN?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  ALLOWED_EMAILS?: string;
  WELLFOUND_SESSION_COOKIE?: string;
  WELLFOUND_CSRF_TOKEN?: string;
}

interface StoredAccessToken {
  accessToken: string;
  refreshToken: string;
  userId: string;
  email: string;
  name: string;
  picture?: string;
  clientId: string;
  scope: string;
  createdAt: number;
  expiresAt: number;
}

interface UserAccountConnection {
  userId: string;
  email: string;
  name: string;
  picture?: string;
  wellfoundSessionCookie?: string;
  wellfoundCsrfToken?: string;
  connectedAt?: string;
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, Mcp-Session-Id',
};

const WELLFOUND_TOOLS = [
  {
    name: 'search_wellfound_jobs',
    description:
      'Search startup jobs on Wellfound (wellfound.com/jobs) by role slug, location slug, remote preference, and page number.',
    inputSchema: {
      type: 'object',
      properties: {
        role_slug: { type: 'string', description: 'Role slug (e.g., "software-engineer", "ai-engineer", "rust-developer")' },
        location_slug: { type: 'string', description: 'Location slug (e.g., "india", "hyderabad", "bangalore", "remote")' },
        remote: { type: 'boolean', description: 'Filter for remote jobs only' },
        job_type: { type: 'string', enum: ['full-time', 'contract', 'internship', 'cofounder'] },
        page: { type: 'number', description: '1-based page number (default: 1)' },
      },
    },
  },
  {
    name: 'get_wellfound_job_details',
    description: 'Retrieve full details for a specific Wellfound job listing including job ID, salary, equity, description, and screening questions.',
    inputSchema: {
      type: 'object',
      properties: {
        job_slug: { type: 'string', description: 'Wellfound job slug or full job URL' },
      },
      required: ['job_slug'],
    },
  },
  {
    name: 'get_wellfound_company',
    description: 'Get startup overview, funding stage, total raised, team size, and open positions for a company on Wellfound.',
    inputSchema: {
      type: 'object',
      properties: {
        company_slug: { type: 'string', description: 'Company slug from wellfound.com/company/<slug>' },
      },
      required: ['company_slug'],
    },
  },
  {
    name: 'list_wellfound_applications',
    description: 'List your active and past job applications on Wellfound (uses your stored OAuth-linked Wellfound session).',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', description: '1-based page number (default: 1)' },
      },
    },
  },
  {
    name: 'apply_to_wellfound_job',
    description: 'WRITE OPERATION: Submit a job application on Wellfound with a custom cover note/pitch. Supports dry_run=true.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: { type: 'string', description: 'Numeric Wellfound job listing ID' },
        job_slug: { type: 'string', description: 'Optional job slug to auto-resolve job_id' },
        note: { type: 'string', description: 'Personalized application cover pitch sent to the hiring manager' },
        answers: {
          type: 'array',
          items: {
            type: 'object',
            properties: { questionId: { type: 'string' }, answer: { type: 'string' } },
            required: ['questionId', 'answer'],
          },
        },
        dry_run: { type: 'boolean', description: 'Preview payload without submitting (default: false)' },
      },
      required: ['note'],
    },
  },
  {
    name: 'save_wellfound_job',
    description: 'WRITE OPERATION: Bookmark/save or unsave a job listing on Wellfound.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: { type: 'string' },
        saved: { type: 'boolean', description: 'true to save, false to unsave (default: true)' },
      },
      required: ['job_id'],
    },
  },
  {
    name: 'send_wellfound_message',
    description: 'WRITE OPERATION: Send a follow-up message inside an existing Wellfound application/recruiter conversation thread.',
    inputSchema: {
      type: 'object',
      properties: {
        thread_id: { type: 'string' },
        body: { type: 'string' },
      },
      required: ['thread_id', 'body'],
    },
  },
  {
    name: 'update_wellfound_profile_headline',
    description: 'WRITE OPERATION: Update your Wellfound candidate bio/headline or job-search status.',
    inputSchema: {
      type: 'object',
      properties: {
        headline: { type: 'string' },
        job_search_status: { type: 'string', enum: ['ACTIVE', 'OPEN', 'CLOSED'] },
      },
    },
  },
  {
    name: 'connection_status',
    description: 'Check your authenticated Google identity, whether your Wellfound session is connected, and get links to manage or disconnect your account.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'disconnect_wellfound_account',
    description: 'Disconnect your stored Wellfound session credentials and optionally revoke your current MCP OAuth access token.',
    inputSchema: {
      type: 'object',
      properties: {
        revoke_mcp_token: {
          type: 'boolean',
          description: 'If true, also revokes the active MCP OAuth bearer token so the client must re-authenticate (default: false).',
        },
      },
    },
  },
];

function randomToken(prefix: string): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${hex}`;
}

async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

class OAuthManager {
  static hasGoogleOAuth(env: Env): boolean {
    return Boolean((env.GOOGLE_CLIENT_ID || '').trim() && (env.GOOGLE_CLIENT_SECRET || '').trim());
  }

  static isEmailAllowed(email: string, env: Env): boolean {
    const allowlist = (env.ALLOWED_EMAILS || '').trim();
    if (!allowlist) return true;
    const allowed = allowlist.split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);
    return allowed.includes(email.toLowerCase());
  }

  static async verifyBearer(request: Request, env: Env): Promise<{ authorized: boolean; tokenRecord?: StoredAccessToken; isStaticToken?: boolean; reason?: string }> {
    const authHeader = request.headers.get('Authorization') || '';
    const apiKeyHeader = request.headers.get('X-API-Key') || '';
    const url = new URL(request.url);
    const queryToken = url.searchParams.get('token') || '';

    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const provided = bearer || apiKeyHeader.trim() || queryToken.trim();

    if (!provided) {
      return { authorized: false, reason: 'Missing Bearer token. Complete OAuth login or pass Authorization header.' };
    }

    // 1. Check KV-backed OAuth 2.1 access token
    if (env.OAUTH_KV) {
      const raw = await env.OAUTH_KV.get(`oauth_access:${provided}`);
      if (raw) {
        const parsed: StoredAccessToken = JSON.parse(raw);
        if (parsed.expiresAt > Date.now()) {
          return { authorized: true, tokenRecord: parsed };
        }
        await env.OAUTH_KV.delete(`oauth_access:${provided}`);
        return { authorized: false, reason: 'OAuth access token expired. Refresh or re-authenticate.' };
      }
    }

    // 2. Fallback check against static MCP_AUTH_TOKEN secret if configured
    const staticToken = (env.MCP_AUTH_TOKEN || '').trim();
    if (staticToken && provided === staticToken) {
      return { authorized: true, isStaticToken: true };
    }

    return { authorized: false, reason: 'Invalid or revoked OAuth token.' };
  }

  static async getUserAccount(env: Env, userId: string): Promise<UserAccountConnection | null> {
    if (!env.OAUTH_KV || !userId) return null;
    const raw = await env.OAUTH_KV.get(`user_conn:${userId}`);
    return raw ? JSON.parse(raw) : null;
  }

  static async saveUserAccount(env: Env, conn: UserAccountConnection): Promise<void> {
    if (!env.OAUTH_KV) return;
    await env.OAUTH_KV.put(`user_conn:${conn.userId}`, JSON.stringify(conn));
  }

  static async disconnectUser(env: Env, userId: string): Promise<void> {
    if (!env.OAUTH_KV || !userId) return;
    const existing = await this.getUserAccount(env, userId);
    if (existing) {
      delete existing.wellfoundSessionCookie;
      delete existing.wellfoundCsrfToken;
      delete existing.connectedAt;
      await this.saveUserAccount(env, existing);
    }
  }

  static async revokeAccessToken(env: Env, accessToken: string): Promise<void> {
    if (!env.OAUTH_KV || !accessToken) return;
    const raw = await env.OAUTH_KV.get(`oauth_access:${accessToken}`);
    if (raw) {
      const parsed: StoredAccessToken = JSON.parse(raw);
      await env.OAUTH_KV.delete(`oauth_access:${accessToken}`);
      if (parsed.refreshToken) {
        await env.OAUTH_KV.delete(`oauth_refresh:${parsed.refreshToken}`);
      }
    }
  }
}

class WellfoundClient {
  private baseUrl: string;
  private sessionCookie: string;
  private csrfToken: string;

  constructor(env: Env, userConn?: UserAccountConnection | null) {
    this.baseUrl = (env.WELLFOUND_BASE_URL || 'https://wellfound.com').replace(/\/$/, '');
    this.sessionCookie = (userConn?.wellfoundSessionCookie || env.WELLFOUND_SESSION_COOKIE || '').trim();
    this.csrfToken = (userConn?.wellfoundCsrfToken || env.WELLFOUND_CSRF_TOKEN || '').trim();
  }

  public isAuthenticated(): boolean {
    return Boolean(this.sessionCookie);
  }

  private buildHeaders(isGraphQL = false): Record<string, string> {
    const headers: Record<string, string> = {
      'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      Accept: isGraphQL ? 'application/json' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      Referer: `${this.baseUrl}/jobs`,
    };

    if (this.sessionCookie) {
      headers['Cookie'] = this.sessionCookie.includes('=')
        ? this.sessionCookie
        : `_wellfound=${this.sessionCookie}`;
    }
    if (isGraphQL) {
      headers['Content-Type'] = 'application/json';
      headers['Origin'] = this.baseUrl;
      headers['X-Requested-With'] = 'XMLHttpRequest';
      if (this.csrfToken) {
        headers['X-CSRF-Token'] = this.csrfToken;
      }
    }
    return headers;
  }

  private async executeGraphQL(operationName: string, query: string, variables: Record<string, any>) {
    if (!this.isAuthenticated()) {
      return {
        ok: false,
        status: 401,
        error: 'Wellfound account is not connected. Open /account on your MCP Worker URL to connect your Wellfound session.',
      };
    }

    const res = await fetch(`${this.baseUrl}/graphql`, {
      method: 'POST',
      headers: this.buildHeaders(true),
      body: JSON.stringify({ operationName, query, variables }),
    });

    const rawText = await res.text();
    let parsed: any = null;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      parsed = { raw: rawText.slice(0, 500) };
    }

    return {
      ok: res.ok && !parsed?.errors,
      status: res.status,
      data: parsed?.data || null,
      errors: parsed?.errors || null,
      raw: !parsed?.data && !parsed?.errors ? parsed : undefined,
      hint:
        res.status === 403
          ? 'Blocked by Wellfound DataDome/CSRF check. Reconnect a fresh _wellfound cookie + X-CSRF-Token in /account.'
          : undefined,
    };
  }

  private extractEmbeddedState(html: string): any {
    const nextDataMatch = html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/i);
    if (nextDataMatch?.[1]) {
      try {
        return JSON.parse(nextDataMatch[1]);
      } catch {
        // Fallback to Apollo state
      }
    }
    const apolloMatch = html.match(/window\.__APOLLO_STATE__\s*=\s*(\{[\s\S]*?\});\s*<\/script>/i);
    if (apolloMatch?.[1]) {
      try {
        return { apolloState: JSON.parse(apolloMatch[1]) };
      } catch {
        return null;
      }
    }
    return null;
  }

  private normalizeJobsFromState(state: any, sourceUrl: string) {
    if (!state) return [];
    const jobs: any[] = [];
    const apollo = state?.props?.pageProps?.apolloState?.data || state?.apolloState || {};

    for (const [key, val] of Object.entries<any>(apollo)) {
      if (key.startsWith('JobListing:') || key.startsWith('StartupJob:')) {
        const startupRef = val?.startup?.__ref ? apollo[val.startup.__ref] : val?.startup;
        jobs.push({
          id: val.id || key.split(':')[1],
          slug: val.slug || '',
          title: val.title || '',
          compensation: val.compensation || val.salary || null,
          equity: val.equity || null,
          remote: val.remote ?? null,
          jobType: val.jobType || null,
          locations: val.locationNames || [],
          liveStartAt: val.liveStartAt || null,
          company: startupRef
            ? {
                name: startupRef.name || '',
                slug: startupRef.slug || '',
                highConcept: startupRef.highConcept || '',
                companySize: startupRef.companySize || '',
                fundingStage: startupRef.stage || null,
                totalRaised: startupRef.totalRaised || null,
              }
            : null,
          url: val.slug ? `${this.baseUrl}/jobs/${val.slug}` : sourceUrl,
        });
      }
    }
    return jobs;
  }

  private buildBrowseUrl(args: any): string {
    const role = args.role_slug ? String(args.role_slug).trim().toLowerCase() : '';
    const location = args.location_slug ? String(args.location_slug).trim().toLowerCase() : '';
    const page = Number(args.page) > 1 ? `?page=${Number(args.page)}` : '';

    if (role && location) return `${this.baseUrl}/role/l/${encodeURIComponent(role)}/${encodeURIComponent(location)}${page}`;
    if (role) return `${this.baseUrl}/role/${encodeURIComponent(role)}${page}`;
    if (args.remote) return `${this.baseUrl}/remote${page}`;
    if (location) return `${this.baseUrl}/location/${encodeURIComponent(location)}${page}`;
    return `${this.baseUrl}/jobs${page}`;
  }

  async searchJobs(args: any) {
    const targetUrl = this.buildBrowseUrl(args);

    if (this.isAuthenticated() && this.csrfToken) {
      const gql = await this.executeGraphQL(
        'JobSearch',
        `query JobSearch($page: Int, $roleSlug: String, $locationSlug: String, $remote: Boolean, $jobTypes: [String]) {
          jobListings(page: $page, roleSlug: $roleSlug, locationSlug: $locationSlug, remote: $remote, jobTypes: $jobTypes) {
            totalCount
            edges {
              node {
                id slug title compensation equity remote jobType locationNames liveStartAt
                startup { id name slug highConcept companySize }
              }
            }
          }
        }`,
        {
          page: Number(args.page) || 1,
          roleSlug: args.role_slug || null,
          locationSlug: args.location_slug || null,
          remote: typeof args.remote === 'boolean' ? args.remote : null,
          jobTypes: args.job_type ? [args.job_type] : null,
        }
      );

      if (gql.ok && gql.data?.jobListings) {
        return { source: 'wellfound-graphql-authenticated', queryUrl: targetUrl, data: gql.data.jobListings };
      }
    }

    const res = await fetch(targetUrl, { headers: this.buildHeaders(false) });
    const html = await res.text();
    const state = this.extractEmbeddedState(html);
    let jobs = this.normalizeJobsFromState(state, targetUrl);

    if (typeof args.remote === 'boolean') jobs = jobs.filter((j) => j.remote === args.remote);
    if (args.job_type) jobs = jobs.filter((j) => String(j.jobType || '').toLowerCase() === String(args.job_type).toLowerCase());

    return {
      source: this.isAuthenticated() ? 'wellfound-ssr-authenticated' : 'wellfound-ssr-public',
      authenticated: this.isAuthenticated(),
      httpStatus: res.status,
      queryUrl: targetUrl,
      totalFound: jobs.length,
      jobs,
    };
  }

  async getJobDetails(jobSlugOrUrl: string) {
    const cleanSlug = jobSlugOrUrl.replace(/^https?:\/\/wellfound\.com\/jobs\//, '').replace(/^\/+|\/+$/g, '');
    const targetUrl = `${this.baseUrl}/jobs/${cleanSlug}`;

    const res = await fetch(targetUrl, { headers: this.buildHeaders(false) });
    const html = await res.text();
    const state = this.extractEmbeddedState(html);
    const jobs = this.normalizeJobsFromState(state, targetUrl);

    const apollo = state?.props?.pageProps?.apolloState?.data || state?.apolloState || {};
    const detailedEntry = Object.entries<any>(apollo).find(([k]) => k.startsWith('JobListing:'))?.[1];

    return {
      authenticated: this.isAuthenticated(),
      httpStatus: res.status,
      url: targetUrl,
      job: detailedEntry
        ? {
            id: detailedEntry.id || cleanSlug.split('-')[0],
            slug: detailedEntry.slug || cleanSlug,
            title: detailedEntry.title,
            description: detailedEntry.description || detailedEntry.descriptionHtml || null,
            compensation: detailedEntry.compensation || null,
            equity: detailedEntry.equity || null,
            remote: detailedEntry.remote ?? null,
            jobType: detailedEntry.jobType || null,
            locations: detailedEntry.locationNames || [],
            skills: detailedEntry.skills || [],
            screeningQuestions: detailedEntry.screeningQuestions || [],
          }
        : jobs[0] || { id: cleanSlug.split('-')[0], slug: cleanSlug },
    };
  }

  async getCompany(companySlug: string) {
    const cleanSlug = companySlug.replace(/^https?:\/\/wellfound\.com\/company\//, '').replace(/^\/+|\/+$/g, '');
    const targetUrl = `${this.baseUrl}/company/${cleanSlug}`;

    const res = await fetch(targetUrl, { headers: this.buildHeaders(false) });
    const html = await res.text();
    const state = this.extractEmbeddedState(html);
    const apollo = state?.props?.pageProps?.apolloState?.data || state?.apolloState || {};
    const startup = Object.entries<any>(apollo).find(([k]) => k.startsWith('Startup:'))?.[1];
    const jobs = this.normalizeJobsFromState(state, `${targetUrl}/jobs`);

    return {
      authenticated: this.isAuthenticated(),
      httpStatus: res.status,
      url: targetUrl,
      company: startup
        ? {
            id: startup.id,
            name: startup.name,
            slug: startup.slug || cleanSlug,
            highConcept: startup.highConcept || null,
            description: startup.productDesc || startup.description || null,
            companySize: startup.companySize || null,
            totalRaised: startup.totalRaised || null,
            stage: startup.stage || null,
            websiteUrl: startup.companyUrl || null,
            locations: startup.locations || [],
          }
        : null,
      openJobsCount: jobs.length,
      openJobs: jobs,
    };
  }

  async listApplications(page = 1) {
    if (!this.isAuthenticated()) {
      return {
        authenticated: false,
        error: 'Wellfound session not connected. Connect your account via /account.',
      };
    }

    const targetUrl = `${this.baseUrl}/jobs/applications?page=${page}`;
    const res = await fetch(targetUrl, { headers: this.buildHeaders(false) });
    const html = await res.text();
    const state = this.extractEmbeddedState(html);
    const apollo = state?.props?.pageProps?.apolloState?.data || state?.apolloState || {};

    const applications = Object.entries<any>(apollo)
      .filter(([k]) => k.startsWith('JobApplication:') || k.startsWith('CandidateApplication:'))
      .map(([, val]) => val);

    return { authenticated: true, httpStatus: res.status, page, totalApplications: applications.length, applications };
  }

  async applyToJob(args: { job_id?: string; job_slug?: string; note: string; answers?: any[]; dry_run?: boolean }) {
    let jobId = (args.job_id || '').trim();
    if (!jobId && args.job_slug) {
      const slugPrefix = String(args.job_slug).replace(/^https?:\/\/wellfound\.com\/jobs\//, '').split('-')[0];
      if (/^\d+$/.test(slugPrefix)) {
        jobId = slugPrefix;
      } else {
        const details = await this.getJobDetails(args.job_slug);
        jobId = String(details?.job?.id || '');
      }
    }

    if (!jobId) throw new Error('Provide either a numeric job_id or a valid job_slug.');

    const variables = {
      input: { jobListingId: jobId, note: args.note, questionAnswers: args.answers || [] },
    };

    if (args.dry_run) {
      return {
        dryRun: true,
        authenticated: this.isAuthenticated(),
        csrfConfigured: Boolean(this.csrfToken),
        endpoint: `${this.baseUrl}/graphql`,
        operationName: 'CreateJobApplication',
        payloadPreview: variables,
      };
    }

    const mutation = `mutation CreateJobApplication($input: CreateJobApplicationInput!) {
      createJobApplication(input: $input) {
        jobApplication { id state createdAt note }
        errors { field message }
      }
    }`;

    return this.executeGraphQL('CreateJobApplication', mutation, variables);
  }

  async saveJob(jobId: string, saved = true) {
    const mutation = saved
      ? `mutation SaveJobListing($input: SaveJobListingInput!) { saveJobListing(input: $input) { jobListing { id isSaved } } }`
      : `mutation UnsaveJobListing($input: UnsaveJobListingInput!) { unsaveJobListing(input: $input) { jobListing { id isSaved } } }`;
    return this.executeGraphQL(saved ? 'SaveJobListing' : 'UnsaveJobListing', mutation, {
      input: { jobListingId: String(jobId) },
    });
  }

  async sendMessage(threadId: string, body: string) {
    const mutation = `mutation SendApplicationMessage($input: SendApplicationMessageInput!) {
      sendApplicationMessage(input: $input) { message { id body createdAt } }
    }`;
    return this.executeGraphQL('SendApplicationMessage', mutation, {
      input: { threadId: String(threadId), body },
    });
  }

  async updateProfileHeadline(args: { headline?: string; job_search_status?: string }) {
    const input: Record<string, any> = {};
    if (args.headline !== undefined) input.bio = args.headline;
    if (args.job_search_status !== undefined) input.jobSearchStatus = args.job_search_status;

    const mutation = `mutation UpdateCandidateProfile($input: UpdateCandidateProfileInput!) {
      updateCandidateProfile(input: $input) { talentProfile { id bio jobSearchStatus } }
    }`;
    return this.executeGraphQL('UpdateCandidateProfile', mutation, { input });
  }
}

function renderConnectPage(params: {
  origin: string;
  userEmail: string;
  userName: string;
  hasGoogle: boolean;
  isWellfoundConnected: boolean;
  oauthQuery?: string;
  flashMessage?: string;
}): Response {
  const { origin, userEmail, userName, hasGoogle, isWellfoundConnected, oauthQuery, flashMessage } = params;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Wellfound MCP — Connect & Manage Account</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 2rem 1rem; display: flex; justify-content: center; }
    .card { max-width: 540px; width: 100%; background: #131a2a; border: 1px solid #243049; border-radius: 14px; padding: 2rem; box-shadow: 0 20px 40px rgba(0,0,0,0.45); }
    h1 { font-size: 1.4rem; margin: 0 0 0.4rem; color: #fff; }
    p.sub { color: #94a3b8; font-size: 0.92rem; margin: 0 0 1.4rem; }
    .badge { display: inline-block; padding: 0.25rem 0.65rem; border-radius: 999px; font-size: 0.78rem; font-weight: 600; margin-bottom: 1rem; }
    .badge.ok { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.35); }
    .badge.warn { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.35); }
    .flash { background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.4); color: #93c5fd; padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1.2rem; font-size: 0.88rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; margin: 1rem 0 0.35rem; color: #cbd5e1; }
    input, textarea { width: 100%; box-sizing: border-box; background: #0b0f19; border: 1px solid #2d3b59; color: #f8fafc; border-radius: 8px; padding: 0.65rem 0.8rem; font-size: 0.88rem; font-family: monospace; }
    .btn { display: inline-block; width: 100%; text-align: center; padding: 0.75rem 1rem; border-radius: 8px; border: none; font-weight: 600; font-size: 0.92rem; cursor: pointer; margin-top: 1rem; text-decoration: none; box-sizing: border-box; }
    .btn-primary { background: #2563eb; color: #fff; }
    .btn-primary:hover { background: #1d4ed8; }
    .btn-google { background: #fff; color: #111827; }
    .btn-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }
    .divider { border-top: 1px solid #243049; margin: 1.5rem 0; }
    code { background: #0b0f19; padding: 0.15rem 0.35rem; border-radius: 4px; font-size: 0.82rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Wellfound MCP Connection</h1>
    <p class="sub">Authenticate your MCP client and manage your stored Wellfound session credentials in Cloudflare KV.</p>

    ${flashMessage ? `<div class="flash">${escapeHtml(flashMessage)}</div>` : ''}

    <div>
      <span class="badge ${userEmail ? 'ok' : 'warn'}">
        ${userEmail ? `Signed in: ${escapeHtml(userEmail)}` : 'Not signed in with Google yet'}
      </span>
      <span class="badge ${isWellfoundConnected ? 'ok' : 'warn'}">
        ${isWellfoundConnected ? 'Wellfound Session: Connected' : 'Wellfound Session: Not Connected'}
      </span>
    </div>

    ${
      !userEmail && hasGoogle
        ? `<a class="btn btn-google" href="${escapeHtml(origin)}/auth/google${oauthQuery ? `?${oauthQuery}` : ''}">Continue with Google</a>`
        : ''
    }

    <form method="POST" action="${escapeHtml(origin)}/account/connect">
      ${oauthQuery ? `<input type="hidden" name="oauth_query" value="${escapeHtml(oauthQuery)}" />` : ''}
      ${
        !hasGoogle
          ? `<label>Your Email (Google OAuth Client ID not set yet — Local Mode)</label>
             <input type="email" name="email" value="${escapeHtml(userEmail || 'chintusharma00014@gmail.com')}" required />`
          : `<input type="hidden" name="email" value="${escapeHtml(userEmail)}" />`
      }
      <label>Wellfound Session Cookie (<code>_wellfound</code>) — Optional for public search, required for Apply/Write</label>
      <textarea name="wellfound_cookie" rows="3" placeholder="Paste _wellfound cookie value from DevTools (Application -> Cookies)">${isWellfoundConnected ? '•••••••• (stored in Cloudflare KV — paste new value to rotate)' : ''}</textarea>

      <label>Wellfound CSRF Token (<code>X-CSRF-Token</code>) — Optional</label>
      <input type="text" name="wellfound_csrf" placeholder="Paste X-CSRF-Token header from DevTools Network tab" />

      <button class="btn btn-primary" type="submit">
        ${oauthQuery ? 'Save & Authorize MCP Client' : 'Save Connection to Cloudflare KV'}
      </button>
    </form>

    <div class="divider"></div>

    <form method="POST" action="${escapeHtml(origin)}/account/disconnect">
      <input type="hidden" name="email" value="${escapeHtml(userEmail || 'chintusharma00014@gmail.com')}" />
      <button class="btn btn-danger" type="submit">Disconnect Wellfound Account & Revoke Stored Tokens</button>
    </form>
  </div>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const origin = url.origin;

    // 1. Health Endpoint
    if (url.pathname === '/health') {
      return Response.json(
        {
          status: 'ok',
          service: 'wellfound-mcp-worker',
          version: '2.0.0',
          oauth21Enabled: true,
          googleOAuthConfigured: OAuthManager.hasGoogleOAuth(env),
          kvBound: Boolean(env.OAUTH_KV),
        },
        { headers: CORS_HEADERS }
      );
    }

    // 2. RFC 9728 OAuth 2.1 Protected Resource Metadata (MCP Spec 2025/2026)
    if (
      url.pathname === '/.well-known/oauth-protected-resource' ||
      url.pathname === '/.well-known/oauth-protected-resource/mcp'
    ) {
      return Response.json(
        {
          resource: `${origin}/mcp`,
          authorization_servers: [origin],
          scopes_supported: ['wellfound:read', 'wellfound:write'],
          bearer_methods_supported: ['header'],
        },
        { headers: CORS_HEADERS }
      );
    }

    // 3. RFC 8414 OAuth 2.1 Authorization Server Metadata
    if (
      url.pathname === '/.well-known/oauth-authorization-server' ||
      url.pathname === '/.well-known/openid-configuration'
    ) {
      return Response.json(
        {
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          registration_endpoint: `${origin}/register`,
          revocation_endpoint: `${origin}/revoke`,
          scopes_supported: ['wellfound:read', 'wellfound:write'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
        },
        { headers: CORS_HEADERS }
      );
    }

    // 4. RFC 7591 Dynamic Client Registration (/register)
    if (url.pathname === '/register' && request.method === 'POST') {
      let body: any = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }
      const clientId = randomToken('wf_client');
      const clientRecord = {
        client_id: clientId,
        client_name: body.client_name || 'MCP Client',
        redirect_uris: body.redirect_uris || [],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        created_at: Date.now(),
      };
      if (env.OAUTH_KV) {
        await env.OAUTH_KV.put(`oauth_client:${clientId}`, JSON.stringify(clientRecord), { expirationTtl: 86400 * 90 });
      }
      return Response.json(clientRecord, { status: 201, headers: CORS_HEADERS });
    }

    // 5. OAuth 2.1 Authorization Endpoint (/authorize)
    if (url.pathname === '/authorize' && request.method === 'GET') {
      const oauthParams = {
        client_id: url.searchParams.get('client_id') || '',
        redirect_uri: url.searchParams.get('redirect_uri') || '',
        response_type: url.searchParams.get('response_type') || 'code',
        scope: url.searchParams.get('scope') || 'wellfound:read wellfound:write',
        state: url.searchParams.get('state') || '',
        code_challenge: url.searchParams.get('code_challenge') || '',
        code_challenge_method: url.searchParams.get('code_challenge_method') || 'S256',
        resource: url.searchParams.get('resource') || `${origin}/mcp`,
      };

      const txId = randomToken('tx');
      if (env.OAUTH_KV) {
        await env.OAUTH_KV.put(`oauth_tx:${txId}`, JSON.stringify(oauthParams), { expirationTtl: 600 });
      }

      // If Google OAuth credentials are configured, redirect straight to Google Sign-In
      if (OAuthManager.hasGoogleOAuth(env)) {
        const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        googleAuthUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID!);
        googleAuthUrl.searchParams.set('redirect_uri', `${origin}/callback`);
        googleAuthUrl.searchParams.set('response_type', 'code');
        googleAuthUrl.searchParams.set('scope', 'openid email profile');
        googleAuthUrl.searchParams.set('state', txId);
        googleAuthUrl.searchParams.set('access_type', 'offline');
        googleAuthUrl.searchParams.set('prompt', 'consent');
        return Response.redirect(googleAuthUrl.toString(), 302);
      }

      // Otherwise render the interactive Connect & Authorize screen
      const existingConn = await OAuthManager.getUserAccount(env, 'chintusharma00014@gmail.com');
      return renderConnectPage({
        origin,
        userEmail: existingConn?.email || '',
        userName: existingConn?.name || '',
        hasGoogle: false,
        isWellfoundConnected: Boolean(existingConn?.wellfoundSessionCookie || env.WELLFOUND_SESSION_COOKIE),
        oauthQuery: `tx=${encodeURIComponent(txId)}`,
      });
    }

    // 6. Direct Google Sign-In trigger from /account
    if (url.pathname === '/auth/google' && request.method === 'GET') {
      if (!OAuthManager.hasGoogleOAuth(env)) {
        return Response.redirect(`${origin}/account`, 302);
      }
      const txId = url.searchParams.get('tx') || randomToken('acct_tx');
      if (!url.searchParams.get('tx') && env.OAUTH_KV) {
        await env.OAUTH_KV.put(`oauth_tx:${txId}`, JSON.stringify({ accountPortalOnly: true }), { expirationTtl: 600 });
      }
      const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      googleAuthUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID!);
      googleAuthUrl.searchParams.set('redirect_uri', `${origin}/callback`);
      googleAuthUrl.searchParams.set('response_type', 'code');
      googleAuthUrl.searchParams.set('scope', 'openid email profile');
      googleAuthUrl.searchParams.set('state', txId);
      return Response.redirect(googleAuthUrl.toString(), 302);
    }

    // 7. Google OAuth Callback (/callback)
    if (url.pathname === '/callback' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      const txId = url.searchParams.get('state') || '';
      if (!code || !env.OAUTH_KV) {
        return new Response('Missing OAuth authorization code or state.', { status: 400 });
      }

      const txRaw = await env.OAUTH_KV.get(`oauth_tx:${txId}`);
      if (!txRaw) {
        return new Response('OAuth transaction expired or invalid.', { status: 400 });
      }
      const tx = JSON.parse(txRaw);

      // Exchange Google code for user profile
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID!,
          client_secret: env.GOOGLE_CLIENT_SECRET!,
          redirect_uri: `${origin}/callback`,
          grant_type: 'authorization_code',
        }),
      });
      const tokenJson: any = await tokenRes.json();
      if (!tokenRes.ok || !tokenJson.access_token) {
        return new Response(`Google OAuth exchange failed: ${JSON.stringify(tokenJson)}`, { status: 400 });
      }

      const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      });
      const googleUser: any = await userRes.json();
      const email = String(googleUser.email || '').toLowerCase();

      if (!email || !OAuthManager.isEmailAllowed(email, env)) {
        return new Response(`Access denied for Google account: ${email}`, { status: 403 });
      }

      // Persist or merge user account in KV
      const existing = await OAuthManager.getUserAccount(env, email);
      const updated: UserAccountConnection = {
        userId: email,
        email,
        name: googleUser.name || email,
        picture: googleUser.picture,
        wellfoundSessionCookie: existing?.wellfoundSessionCookie,
        wellfoundCsrfToken: existing?.wellfoundCsrfToken,
        connectedAt: existing?.connectedAt,
      };
      await OAuthManager.saveUserAccount(env, updated);

      if (tx.accountPortalOnly) {
        return renderConnectPage({
          origin,
          userEmail: email,
          userName: updated.name,
          hasGoogle: true,
          isWellfoundConnected: Boolean(updated.wellfoundSessionCookie),
          flashMessage: `Signed in with Google as ${email}.`,
        });
      }

      // Issue MCP OAuth authorization code back to the MCP client
      const authCode = randomToken('wf_code');
      await env.OAUTH_KV.put(
        `oauth_code:${authCode}`,
        JSON.stringify({
          ...tx,
          userId: email,
          email,
          name: updated.name,
          picture: updated.picture,
        }),
        { expirationTtl: 300 }
      );
      await env.OAUTH_KV.delete(`oauth_tx:${txId}`);

      const redirectTarget = new URL(tx.redirect_uri);
      redirectTarget.searchParams.set('code', authCode);
      if (tx.state) redirectTarget.searchParams.set('state', tx.state);
      return Response.redirect(redirectTarget.toString(), 302);
    }

    // 8. Account Management Portal (/account, /account/connect, /account/disconnect)
    if (url.pathname === '/account' && request.method === 'GET') {
      const emailParam = url.searchParams.get('email') || 'chintusharma00014@gmail.com';
      const existing = await OAuthManager.getUserAccount(env, emailParam);
      return renderConnectPage({
        origin,
        userEmail: existing?.email || '',
        userName: existing?.name || '',
        hasGoogle: OAuthManager.hasGoogleOAuth(env),
        isWellfoundConnected: Boolean(existing?.wellfoundSessionCookie || env.WELLFOUND_SESSION_COOKIE),
      });
    }

    if (url.pathname === '/account/connect' && request.method === 'POST') {
      const form = await request.formData();
      const email = String(form.get('email') || 'chintusharma00014@gmail.com').trim().toLowerCase();
      const cookieInput = String(form.get('wellfound_cookie') || '').trim();
      const csrfInput = String(form.get('wellfound_csrf') || '').trim();
      const oauthQuery = String(form.get('oauth_query') || '').trim();

      if (!OAuthManager.isEmailAllowed(email, env)) {
        return new Response(`Email ${email} is not in ALLOWED_EMAILS.`, { status: 403 });
      }

      const existing = await OAuthManager.getUserAccount(env, email);
      const isPlaceholder = cookieInput.startsWith('••••');
      const updated: UserAccountConnection = {
        userId: email,
        email,
        name: existing?.name || email.split('@')[0],
        picture: existing?.picture,
        wellfoundSessionCookie: !isPlaceholder && cookieInput ? cookieInput : existing?.wellfoundSessionCookie,
        wellfoundCsrfToken: csrfInput || existing?.wellfoundCsrfToken,
        connectedAt: new Date().toISOString(),
      };
      await OAuthManager.saveUserAccount(env, updated);

      // If this came from an MCP client /authorize flow, complete the OAuth redirect
      if (oauthQuery.startsWith('tx=') && env.OAUTH_KV) {
        const txId = decodeURIComponent(oauthQuery.slice(3));
        const txRaw = await env.OAUTH_KV.get(`oauth_tx:${txId}`);
        if (txRaw) {
          const tx = JSON.parse(txRaw);
          const authCode = randomToken('wf_code');
          await env.OAUTH_KV.put(
            `oauth_code:${authCode}`,
            JSON.stringify({ ...tx, userId: email, email, name: updated.name }),
            { expirationTtl: 300 }
          );
          await env.OAUTH_KV.delete(`oauth_tx:${txId}`);
          const redirectTarget = new URL(tx.redirect_uri);
          redirectTarget.searchParams.set('code', authCode);
          if (tx.state) redirectTarget.searchParams.set('state', tx.state);
          return Response.redirect(redirectTarget.toString(), 302);
        }
      }

      return renderConnectPage({
        origin,
        userEmail: email,
        userName: updated.name,
        hasGoogle: OAuthManager.hasGoogleOAuth(env),
        isWellfoundConnected: Boolean(updated.wellfoundSessionCookie),
        flashMessage: 'Saved connection credentials in Cloudflare KV.',
      });
    }

    if (url.pathname === '/account/disconnect' && request.method === 'POST') {
      const form = await request.formData();
      const email = String(form.get('email') || 'chintusharma00014@gmail.com').trim().toLowerCase();
      await OAuthManager.disconnectUser(env, email);

      return renderConnectPage({
        origin,
        userEmail: email,
        userName: email.split('@')[0],
        hasGoogle: OAuthManager.hasGoogleOAuth(env),
        isWellfoundConnected: false,
        flashMessage: `Disconnected Wellfound session for ${email} from Cloudflare KV.`,
      });
    }

    // 9. OAuth 2.1 Token Endpoint (/token) — supports authorization_code (PKCE) & refresh_token
    if (url.pathname === '/token' && request.method === 'POST') {
      let params: URLSearchParams;
      const contentType = request.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        const j: any = await request.json();
        params = new URLSearchParams(j);
      } else {
        params = new URLSearchParams(await request.text());
      }

      const grantType = params.get('grant_type');
      if (!env.OAUTH_KV) {
        return Response.json({ error: 'server_error', error_description: 'OAUTH_KV not bound' }, { status: 500, headers: CORS_HEADERS });
      }

      if (grantType === 'authorization_code') {
        const code = params.get('code') || '';
        const codeVerifier = params.get('code_verifier') || '';
        const codeRaw = await env.OAUTH_KV.get(`oauth_code:${code}`);
        if (!codeRaw) {
          return Response.json({ error: 'invalid_grant', error_description: 'Authorization code invalid or expired' }, { status: 400, headers: CORS_HEADERS });
        }
        const codeRecord = JSON.parse(codeRaw);
        await env.OAUTH_KV.delete(`oauth_code:${code}`);

        if (codeRecord.code_challenge) {
          const computed = await sha256Base64Url(codeVerifier);
          if (computed !== codeRecord.code_challenge) {
            return Response.json({ error: 'invalid_grant', error_description: 'PKCE code_verifier mismatch' }, { status: 400, headers: CORS_HEADERS });
          }
        }

        const accessToken = randomToken('wf_at');
        const refreshToken = randomToken('wf_rt');
        const expiresIn = 86400 * 7; // 7 days
        const record: StoredAccessToken = {
          accessToken,
          refreshToken,
          userId: codeRecord.userId,
          email: codeRecord.email,
          name: codeRecord.name,
          picture: codeRecord.picture,
          clientId: codeRecord.client_id,
          scope: codeRecord.scope || 'wellfound:read wellfound:write',
          createdAt: Date.now(),
          expiresAt: Date.now() + expiresIn * 1000,
        };

        await env.OAUTH_KV.put(`oauth_access:${accessToken}`, JSON.stringify(record), { expirationTtl: expiresIn });
        await env.OAUTH_KV.put(`oauth_refresh:${refreshToken}`, JSON.stringify(record), { expirationTtl: 86400 * 30 });

        return Response.json(
          {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: expiresIn,
            refresh_token: refreshToken,
            scope: record.scope,
          },
          { headers: CORS_HEADERS }
        );
      }

      if (grantType === 'refresh_token') {
        const refreshToken = params.get('refresh_token') || '';
        const refRaw = await env.OAUTH_KV.get(`oauth_refresh:${refreshToken}`);
        if (!refRaw) {
          return Response.json({ error: 'invalid_grant', error_description: 'Refresh token invalid or revoked' }, { status: 400, headers: CORS_HEADERS });
        }
        const oldRecord: StoredAccessToken = JSON.parse(refRaw);
        await env.OAUTH_KV.delete(`oauth_access:${oldRecord.accessToken}`);

        const newAccessToken = randomToken('wf_at');
        const expiresIn = 86400 * 7;
        const updated: StoredAccessToken = {
          ...oldRecord,
          accessToken: newAccessToken,
          createdAt: Date.now(),
          expiresAt: Date.now() + expiresIn * 1000,
        };
        await env.OAUTH_KV.put(`oauth_access:${newAccessToken}`, JSON.stringify(updated), { expirationTtl: expiresIn });
        await env.OAUTH_KV.put(`oauth_refresh:${refreshToken}`, JSON.stringify(updated), { expirationTtl: 86400 * 30 });

        return Response.json(
          {
            access_token: newAccessToken,
            token_type: 'Bearer',
            expires_in: expiresIn,
            refresh_token: refreshToken,
            scope: updated.scope,
          },
          { headers: CORS_HEADERS }
        );
      }

      return Response.json({ error: 'unsupported_grant_type' }, { status: 400, headers: CORS_HEADERS });
    }

    // 10. OAuth Token Revocation / Disconnect Endpoint (/revoke)
    if (url.pathname === '/revoke' && (request.method === 'POST' || request.method === 'DELETE')) {
      const authHeader = request.headers.get('Authorization') || '';
      let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
      if (!token && request.method === 'POST') {
        const text = await request.text();
        const params = new URLSearchParams(text);
        token = params.get('token') || '';
      }
      if (token) {
        await OAuthManager.revokeAccessToken(env, token);
      }
      return Response.json({ revoked: true }, { headers: CORS_HEADERS });
    }

    // 11. Protected MCP Endpoint (/mcp or /) — returns RFC 9728 WWW-Authenticate challenge on 401
    const auth = await OAuthManager.verifyBearer(request, env);
    if (!auth.authorized) {
      return Response.json(
        {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32001, message: auth.reason || 'Unauthorized' },
        },
        {
          status: 401,
          headers: {
            ...CORS_HEADERS,
            'WWW-Authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="wellfound:read wellfound:write"`,
          },
        }
      );
    }

    const userId = auth.tokenRecord?.userId || 'chintusharma00014@gmail.com';
    const userConn = await OAuthManager.getUserAccount(env, userId);
    const client = new WellfoundClient(env, userConn);

    if (request.method === 'GET') {
      return Response.json(
        {
          name: 'wellfound-mcp-worker',
          version: '2.0.0',
          protocol: 'json-rpc',
          user: auth.tokenRecord ? { email: auth.tokenRecord.email, name: auth.tokenRecord.name } : { mode: 'static-bearer' },
          wellfoundAccountConnected: client.isAuthenticated(),
          accountPortalUrl: `${origin}/account`,
          capabilities: { tools: { listChanged: false } },
          tools: WELLFOUND_TOOLS.map((t) => t.name),
        },
        { headers: CORS_HEADERS }
      );
    }

    if (request.method === 'POST') {
      let body: any;
      try {
        body = await request.json();
      } catch {
        return Response.json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, { status: 400, headers: CORS_HEADERS });
      }

      const { method, params = {}, id = null } = body || {};

      try {
        if (method === 'initialize') {
          return Response.json(
            {
              jsonrpc: '2.0',
              id,
              result: {
                protocolVersion: '2024-11-05',
                capabilities: { tools: { listChanged: false } },
                serverInfo: { name: 'wellfound-mcp-worker', version: '2.0.0' },
              },
            },
            { headers: CORS_HEADERS }
          );
        }

        if (method === 'notifications/initialized') {
          return new Response(null, { status: 204, headers: CORS_HEADERS });
        }

        if (method === 'ping') {
          return Response.json({ jsonrpc: '2.0', id, result: {} }, { headers: CORS_HEADERS });
        }

        if (method === 'tools/list') {
          return Response.json({ jsonrpc: '2.0', id, result: { tools: WELLFOUND_TOOLS } }, { headers: CORS_HEADERS });
        }

        if (method === 'tools/call') {
          const toolName = params?.name;
          const args = params?.arguments || {};
          let resultData: any;

          switch (toolName) {
            case 'search_wellfound_jobs':
              resultData = await client.searchJobs(args);
              break;
            case 'get_wellfound_job_details':
              if (!args.job_slug) throw new Error('job_slug is required');
              resultData = await client.getJobDetails(String(args.job_slug));
              break;
            case 'get_wellfound_company':
              if (!args.company_slug) throw new Error('company_slug is required');
              resultData = await client.getCompany(String(args.company_slug));
              break;
            case 'list_wellfound_applications':
              resultData = await client.listApplications(Number(args.page) || 1);
              break;
            case 'apply_to_wellfound_job':
              if (!args.note) throw new Error('note (cover pitch) is required');
              resultData = await client.applyToJob({
                job_id: args.job_id,
                job_slug: args.job_slug,
                note: String(args.note),
                answers: args.answers,
                dry_run: Boolean(args.dry_run),
              });
              break;
            case 'save_wellfound_job':
              if (!args.job_id) throw new Error('job_id is required');
              resultData = await client.saveJob(String(args.job_id), args.saved !== false);
              break;
            case 'send_wellfound_message':
              if (!args.thread_id || !args.body) throw new Error('thread_id and body are required');
              resultData = await client.sendMessage(String(args.thread_id), String(args.body));
              break;
            case 'update_wellfound_profile_headline':
              resultData = await client.updateProfileHeadline({
                headline: args.headline,
                job_search_status: args.job_search_status,
              });
              break;
            case 'connection_status':
              resultData = {
                authenticatedUser: auth.tokenRecord
                  ? { email: auth.tokenRecord.email, name: auth.tokenRecord.name }
                  : { email: userId, authMethod: 'static_bearer' },
                wellfoundSessionConnected: client.isAuthenticated(),
                connectedAt: userConn?.connectedAt || null,
                manageAccountUrl: `${origin}/account?email=${encodeURIComponent(userId)}`,
              };
              break;
            case 'disconnect_wellfound_account':
              await OAuthManager.disconnectUser(env, userId);
              if (args.revoke_mcp_token && auth.tokenRecord?.accessToken) {
                await OAuthManager.revokeAccessToken(env, auth.tokenRecord.accessToken);
              }
              resultData = {
                disconnected: true,
                userId,
                wellfoundSessionCleared: true,
                mcpTokenRevoked: Boolean(args.revoke_mcp_token && auth.tokenRecord?.accessToken),
                reconnectUrl: `${origin}/account?email=${encodeURIComponent(userId)}`,
              };
              break;
            default:
              return Response.json(
                { jsonrpc: '2.0', id, error: { code: -32601, message: `Tool '${toolName}' not found` } },
                { status: 404, headers: CORS_HEADERS }
              );
          }

          return Response.json(
            {
              jsonrpc: '2.0',
              id,
              result: {
                content: [
                  {
                    type: 'text',
                    text: typeof resultData === 'string' ? resultData : JSON.stringify(resultData, null, 2),
                  },
                ],
              },
            },
            { headers: CORS_HEADERS }
          );
        }

        return Response.json(
          { jsonrpc: '2.0', id, error: { code: -32601, message: `Method ${method} not found` } },
          { status: 404, headers: CORS_HEADERS }
        );
      } catch (err: any) {
        return Response.json(
          {
            jsonrpc: '2.0',
            id,
            error: { code: -32603, message: `Worker Exception: ${err?.message || String(err)}` },
          },
          { status: 500, headers: CORS_HEADERS }
        );
      }
    }

    return new Response('Method Not Allowed', { status: 405, headers: CORS_HEADERS });
  },
};
