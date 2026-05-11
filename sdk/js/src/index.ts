// @safecadence/sdk — official TypeScript SDK for the SafeCadence NetRisk REST API.
//
// Uses the native global `fetch` (Node >= 18, modern browsers, Deno, Bun). No
// runtime dependencies.

import type {
  Asset,
  ClientOptions,
  ComplianceStatus,
  ComposeReportOptions,
  Finding,
  GenerateJob,
  ListResponse,
  Report,
  Template,
} from "./types";

export * from "./types";

export class SafeCadenceError extends Error {
  public statusCode?: number;
  public responseBody?: string;
  constructor(message: string, statusCode?: number, responseBody?: string) {
    super(message);
    this.name = "SafeCadenceError";
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

export class AuthError extends SafeCadenceError {
  constructor(message: string, statusCode?: number, responseBody?: string) {
    super(message, statusCode, responseBody);
    this.name = "AuthError";
  }
}

export class NotFound extends SafeCadenceError {
  constructor(message: string, statusCode?: number, responseBody?: string) {
    super(message, statusCode, responseBody);
    this.name = "NotFound";
  }
}

export class RateLimitError extends SafeCadenceError {
  public retryAfter?: number;
  constructor(message: string, retryAfter?: number, statusCode?: number,
              responseBody?: string) {
    super(message, statusCode, responseBody);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

function unwrapList<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object" && "items" in data) {
    const items = (data as ListResponse<T>).items;
    return Array.isArray(items) ? items : [];
  }
  return [];
}

export class Client {
  private baseUrl: string;
  private apiKey?: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    if (!opts.baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 30000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "safecadence-sdk-js/0.1.0",
      ...extra,
    };
    if (this.apiKey) h["Authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    opts: {
      params?: Record<string, string | number | undefined>;
      body?: unknown;
      expectBytes?: boolean;
    } = {}
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (opts.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }

    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await this.fetchImpl(url.toString(), {
        method,
        headers: this.headers(opts.body ? { "Content-Type": "application/json" } : undefined),
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: ctl.signal,
      });
    } catch (err) {
      throw new SafeCadenceError(
        `network error: ${(err as Error).message ?? String(err)}`
      );
    } finally {
      clearTimeout(timer);
    }

    const status = resp.status;
    const bodyText = opts.expectBytes ? "" : await resp.text();

    if (status === 401 || status === 403) {
      throw new AuthError(`auth failed (${status})`, status, bodyText);
    }
    if (status === 404) {
      throw new NotFound(`not found: ${path}`, status, bodyText);
    }
    if (status === 429) {
      const retryAfter = Number(resp.headers.get("Retry-After")) || undefined;
      throw new RateLimitError("rate limited", retryAfter, status, bodyText);
    }
    if (status >= 400) {
      throw new SafeCadenceError(
        `HTTP ${status}: ${bodyText.slice(0, 200)}`,
        status,
        bodyText
      );
    }

    if (opts.expectBytes) {
      return (await resp.arrayBuffer()) as unknown as T;
    }
    if (!bodyText) return undefined as unknown as T;
    const ctype = resp.headers.get("Content-Type") ?? "";
    if (ctype.includes("application/json")) {
      return JSON.parse(bodyText) as T;
    }
    return bodyText as unknown as T;
  }

  // ---------------- Inventory ---------------- //

  async listInventory(): Promise<Asset[]> {
    const data = await this.request<unknown>("GET", "/api/v1/inventory");
    return unwrapList<Asset>(data);
  }

  async getAsset(id: string): Promise<Asset> {
    return this.request<Asset>("GET", `/api/v1/inventory/${encodeURIComponent(id)}`);
  }

  // ---------------- Findings + compliance ---------------- //

  async getFindings(filters?: { severity?: string; assetId?: string }): Promise<Finding[]> {
    const data = await this.request<unknown>("GET", "/api/v1/findings", {
      params: { severity: filters?.severity, asset_id: filters?.assetId },
    });
    return unwrapList<Finding>(data);
  }

  async getComplianceStatus(framework?: string): Promise<ComplianceStatus> {
    return this.request<ComplianceStatus>("GET", "/api/v1/compliance/status", {
      params: framework ? { framework } : undefined,
    });
  }

  // ---------------- Reports ---------------- //

  async listReports(): Promise<Report[]> {
    const data = await this.request<unknown>("GET", "/api/v1/reports");
    return unwrapList<Report>(data);
  }

  async composeReport(opts: ComposeReportOptions = {}): Promise<ArrayBuffer> {
    const body: Record<string, unknown> = {
      format: opts.format ?? "html",
    };
    if (opts.preset) body.preset_id = opts.preset;
    if (opts.sections) body.sections = opts.sections;
    if (opts.scope) body.scope = opts.scope;
    if (opts.industry_template_id) body.industry_template_id = opts.industry_template_id;
    if (opts.prepared_for) body.prepared_for = opts.prepared_for;
    if (opts.filename) body.filename = opts.filename;
    return this.request<ArrayBuffer>("POST", "/api/reports/render-download", {
      body,
      expectBytes: true,
    });
  }

  async generateReport(preset: string, format = "pdf"): Promise<GenerateJob> {
    return this.request<GenerateJob>("POST", "/api/v1/reports/generate", {
      body: { preset, format },
    });
  }

  // ---------------- Templates ---------------- //

  async listTemplates(): Promise<Template[]> {
    const data = await this.request<unknown>("GET", "/api/reports/templates");
    return unwrapList<Template>(data);
  }

  async saveTemplate(
    name: string,
    sections: string[],
    scope: Record<string, unknown> = {}
  ): Promise<Template> {
    return this.request<Template>("POST", "/api/reports/templates", {
      body: { name, sections, scope },
    });
  }
}

export default Client;
