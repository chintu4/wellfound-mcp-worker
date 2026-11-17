// Wellfound Jobs Cloudflare Worker MCP Server (Read + Write Operations)
// Supports MCP Protocol (2024-11-05): initialize, ping, notifications/initialized, tools/list, tools/call
// Authentication:
//   1. Client -> MCP Worker: Authorization: Bearer <MCP_AUTH_TOKEN> or X-API-Key
//   2. MCP Worker -> Wellfound: Authenticated _wellfound cookie + X-CSRF-Token (GraphQL mutations & queries)

export interface Env {
  WELLFOUND_BASE_URL?: string;
  MCP_AUTH_TOKEN?: string;
  WELLFOUND_SESSION_COOKIE?: string;
  WELLFOUND_CSRF_TOKEN?: string;
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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
        role_slug: {
          type: 'string',
          description: 'Role slug on Wellfound (e.g., "software-engineer", "ai-engineer", "backend-engineer", "rust-developer")',
        },
        location_slug: {
          type: 'string',
          description: 'Location slug (e.g., "india", "hyderabad", "bangalore", "united-states", "san-francisco")',
        },
        remote: {
          type: 'boolean',
          description: 'Filter for remote jobs only',
        },
        job_type: {
          type: 'string',
          enum: ['full-time', 'contract', 'internship', 'cofounder'],
          description: 'Employment type filter',
        },
        page: {
          type: 'number',
          description: '1-based page number (default: 1)',
        },
      },
    },
  },
  {
    name: 'get_wellfound_job_details',
    description:
      'Retrieve full details for a specific Wellfound job listing including job ID, compensation, equity, full description, and screening questions.',
    inputSchema: {
      type: 'object',
      properties: {
        job_slug: {
          type: 'string',
          description: 'Wellfound job slug or full job URL (e.g., "4791894-senior-ai-developer")',
        },
      },
      required: ['job_slug'],
    },
  },
  {
    name: 'get_wellfound_company',
    description:
      'Get startup overview, funding stage, total raised, team size, and open positions for a company on Wellfound.',
    inputSchema: {
      type: 'object',
      properties: {
        company_slug: {
          type: 'string',
          description: 'Company slug from wellfound.com/company/<slug>',
        },
      },
      required: ['company_slug'],
    },
  },
  {
    name: 'list_wellfound_applications',
    description:
      'List your active and past job applications on Wellfound (requires WELLFOUND_SESSION_COOKIE configured).',
    inputSchema: {
      type: 'object',
      properties: {
        page: {
          type: 'number',
          description: '1-based page number (default: 1)',
        },
      },
    },
  },
  {
    name: 'apply_to_wellfound_job',
    description:
      'WRITE OPERATION: Submit a job application on Wellfound with a custom cover note/pitch to the hiring manager. Supports dry_run=true to preview before sending (applications cannot be undone once submitted).',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: {
          type: 'string',
          description: 'Numeric Wellfound job listing ID (e.g., "4791894"). You can also pass job_slug to auto-resolve the ID.',
        },
        job_slug: {
          type: 'string',
          description: 'Optional job slug if job_id is unknown; the server will resolve the numeric job_id first.',
        },
        note: {
          type: 'string',
          description: 'Personalized application note / cover message sent directly to the recruiter/founder.',
        },
        answers: {
          type: 'array',
          description: 'Optional screening question answers [{ questionId, answer }] if the job requires them.',
          items: {
            type: 'object',
            properties: {
              questionId: { type: 'string' },
              answer: { type: 'string' },
            },
            required: ['questionId', 'answer'],
          },
        },
        dry_run: {
          type: 'boolean',
          description: 'If true, validates authentication and previews the application payload without submitting (default: false).',
        },
      },
      required: ['note'],
    },
  },
  {
    name: 'save_wellfound_job',
    description:
      'WRITE OPERATION: Bookmark/save or unsave a job listing on Wellfound for later review.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: {
          type: 'string',
          description: 'Numeric Wellfound job listing ID (e.g., "4791894")',
        },
        saved: {
          type: 'boolean',
          description: 'true to save/bookmark the job, false to unsave it (default: true)',
        },
      },
      required: ['job_id'],
    },
  },
  {
    name: 'send_wellfound_message',
    description:
      'WRITE OPERATION: Send a follow-up message inside an existing Wellfound application/recruiter conversation thread.',
    inputSchema: {
      type: 'object',
      properties: {
        thread_id: {
          type: 'string',
          description: 'Wellfound conversation / application thread ID from list_wellfound_applications',
        },
        body: {
          type: 'string',
          description: 'Message text to send to the recruiter or founder',
        },
      },
      required: ['thread_id', 'body'],
    },
  },
  {
    name: 'update_wellfound_profile_headline',
    description:
      'WRITE OPERATION: Update your Wellfound candidate bio/headline or job-search status.',
    inputSchema: {
      type: 'object',
      properties: {
        headline: {
          type: 'string',
          description: 'New profile headline / mini-bio (max 160 chars recommended)',
        },
        job_search_status: {
          type: 'string',
          enum: ['ACTIVE', 'OPEN', 'CLOSED'],
          description: 'Candidate availability status: ACTIVE (ready to interview), OPEN (open to offers), CLOSED',
        },
      },
    },
  },
];

class AuthGuard {
  static verify(request: Request, env: Env): { authorized: boolean; reason?: string } {
    const expected = (env.MCP_AUTH_TOKEN || '').trim();
    if (!expected) {
      return { authorized: true };
    }

    const authHeader = request.headers.get('Authorization') || '';
    const apiKeyHeader = request.headers.get('X-API-Key') || '';
    const url = new URL(request.url);
    const queryToken = url.searchParams.get('token') || '';

    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const provided = bearer || apiKeyHeader.trim() || queryToken.trim();

    if (!provided) {
      return { authorized: false, reason: 'Missing Authorization Bearer token or X-API-Key header.' };
    }
    if (provided !== expected) {
      return { authorized: false, reason: 'Invalid MCP authentication token.' };
    }
    return { authorized: true };
  }
}

class WellfoundClient {
  private baseUrl: string;
  private sessionCookie: string;
  private csrfToken: string;

  constructor(env: Env) {
    this.baseUrl = (env.WELLFOUND_BASE_URL || 'https://wellfound.com').replace(/\/$/, '');
    this.sessionCookie = (env.WELLFOUND_SESSION_COOKIE || '').trim();
    this.csrfToken = (env.WELLFOUND_CSRF_TOKEN || '').trim();
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
        error: 'WELLFOUND_SESSION_COOKIE is missing. Configure it in Cloudflare Worker secrets to execute write mutations.',
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
          ? 'Blocked by Wellfound DataDome/CSRF check. Ensure WELLFOUND_SESSION_COOKIE and WELLFOUND_CSRF_TOKEN are fresh from an active browser session.'
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
          remoteConfigKind: val.remoteConfigKind || null,
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

    if (role && location) {
      return `${this.baseUrl}/role/l/${encodeURIComponent(role)}/${encodeURIComponent(location)}${page}`;
    }
    if (role) {
      return `${this.baseUrl}/role/${encodeURIComponent(role)}${page}`;
    }
    if (args.remote) {
      return `${this.baseUrl}/remote${page}`;
    }
    if (location) {
      return `${this.baseUrl}/location/${encodeURIComponent(location)}${page}`;
    }
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
        return {
          source: 'wellfound-graphql-authenticated',
          queryUrl: targetUrl,
          data: gql.data.jobListings,
        };
      }
    }

    const res = await fetch(targetUrl, { headers: this.buildHeaders(false) });
    const html = await res.text();
    const state = this.extractEmbeddedState(html);
    let jobs = this.normalizeJobsFromState(state, targetUrl);

    if (typeof args.remote === 'boolean') {
      jobs = jobs.filter((j) => j.remote === args.remote);
    }
    if (args.job_type) {
      jobs = jobs.filter((j) => String(j.jobType || '').toLowerCase() === String(args.job_type).toLowerCase());
    }

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
        error: 'WELLFOUND_SESSION_COOKIE is not configured in Cloudflare Worker secrets.',
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

    return {
      authenticated: true,
      httpStatus: res.status,
      page,
      totalApplications: applications.length,
      applications,
    };
  }

  // --- WRITE OPERATIONS ---

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

    if (!jobId) {
      throw new Error('Provide either a numeric job_id or a valid job_slug.');
    }

    const variables = {
      input: {
        jobListingId: jobId,
        note: args.note,
        questionAnswers: args.answers || [],
      },
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
        jobApplication {
          id
          state
          createdAt
          note
        }
        errors {
          field
          message
        }
      }
    }`;

    return this.executeGraphQL('CreateJobApplication', mutation, variables);
  }

  async saveJob(jobId: string, saved = true) {
    const mutation = saved
      ? `mutation SaveJobListing($input: SaveJobListingInput!) {
          saveJobListing(input: $input) {
            jobListing { id isSaved }
          }
        }`
      : `mutation UnsaveJobListing($input: UnsaveJobListingInput!) {
          unsaveJobListing(input: $input) {
            jobListing { id isSaved }
          }
        }`;

    return this.executeGraphQL(saved ? 'SaveJobListing' : 'UnsaveJobListing', mutation, {
      input: { jobListingId: String(jobId) },
    });
  }

  async sendMessage(threadId: string, body: string) {
    const mutation = `mutation SendApplicationMessage($input: SendApplicationMessageInput!) {
      sendApplicationMessage(input: $input) {
        message {
          id
          body
          createdAt
        }
      }
    }`;

    return this.executeGraphQL('SendApplicationMessage', mutation, {
      input: {
        threadId: String(threadId),
        body,
      },
    });
  }

  async updateProfileHeadline(args: { headline?: string; job_search_status?: string }) {
    const input: Record<string, any> = {};
    if (args.headline !== undefined) input.bio = args.headline;
    if (args.job_search_status !== undefined) input.jobSearchStatus = args.job_search_status;

    const mutation = `mutation UpdateCandidateProfile($input: UpdateCandidateProfileInput!) {
      updateCandidateProfile(input: $input) {
        talentProfile {
          id
          bio
          jobSearchStatus
        }
      }
    }`;

    return this.executeGraphQL('UpdateCandidateProfile', mutation, { input });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return Response.json(
        {
          status: 'ok',
          service: 'wellfound-mcp-worker',
          version: '1.1.0',
          mcpAuthEnabled: Boolean((env.MCP_AUTH_TOKEN || '').trim()),
          wellfoundSessionConfigured: Boolean((env.WELLFOUND_SESSION_COOKIE || '').trim()),
          wellfoundCsrfConfigured: Boolean((env.WELLFOUND_CSRF_TOKEN || '').trim()),
        },
        { headers: CORS_HEADERS }
      );
    }

    const authCheck = AuthGuard.verify(request, env);
    if (!authCheck.authorized) {
      return Response.json(
        {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32001, message: authCheck.reason || 'Unauthorized' },
        },
        {
          status: 401,
          headers: {
            ...CORS_HEADERS,
            'WWW-Authenticate': 'Bearer realm="wellfound-mcp-worker"',
          },
        }
      );
    }

    const client = new WellfoundClient(env);

    if (request.method === 'GET') {
      return Response.json(
        {
          name: 'wellfound-mcp-worker',
          version: '1.1.0',
          protocol: 'json-rpc',
          auth: {
            mcpTokenProtected: Boolean((env.MCP_AUTH_TOKEN || '').trim()),
            wellfoundSessionAuthenticated: client.isAuthenticated(),
            wellfoundCsrfConfigured: Boolean((env.WELLFOUND_CSRF_TOKEN || '').trim()),
          },
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
        return Response.json(
          { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
          { status: 400, headers: CORS_HEADERS }
        );
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
                serverInfo: { name: 'wellfound-mcp-worker', version: '1.1.0' },
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
          return Response.json(
            { jsonrpc: '2.0', id, result: { tools: WELLFOUND_TOOLS } },
            { headers: CORS_HEADERS }
          );
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
            default:
              return Response.json(
                {
                  jsonrpc: '2.0',
                  id,
                  error: { code: -32601, message: `Tool '${toolName}' not found` },
                },
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
          {
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Method ${method} not found` },
          },
          { status: 404, headers: CORS_HEADERS }
        );
      } catch (err: any) {
        return Response.json(
          {
            jsonrpc: '2.0',
            id,
            error: {
              code: -32603,
              message: `Worker Exception: ${err?.message || String(err)}`,
            },
          },
          { status: 500, headers: CORS_HEADERS }
        );
      }
    }

    return new Response('Method Not Allowed', { status: 405, headers: CORS_HEADERS });
  },
};
