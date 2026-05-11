import { describe, expect, it, vi } from "vitest";
import { Client, AuthError, NotFound, RateLimitError } from "./index";

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const isJson = !(body instanceof ArrayBuffer);
  const bodyStr = isJson ? JSON.stringify(body) : "";
  return vi.fn(async () => {
    const h = new Headers({
      "Content-Type": isJson ? "application/json" : "application/octet-stream",
      ...headers,
    });
    return new Response(isJson ? bodyStr : (body as ArrayBuffer), {
      status,
      headers: h,
    });
  });
}

describe("Client", () => {
  it("lists inventory", async () => {
    const fetchImpl = mockFetch(200, [{ id: "a1", hostname: "core-sw-1" }]);
    const c = new Client({ baseUrl: "https://x.example.com", apiKey: "k", fetchImpl });
    const items = await c.listInventory();
    expect(items[0].hostname).toBe("core-sw-1");
    const url = (fetchImpl.mock.calls[0][0] as string);
    expect(url).toContain("/api/v1/inventory");
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer k");
  });

  it("unwraps items envelope", async () => {
    const fetchImpl = mockFetch(200, { items: [{ id: "x" }, { id: "y" }], total: 2 });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    const items = await c.listInventory();
    expect(items).toHaveLength(2);
  });

  it("gets one asset", async () => {
    const fetchImpl = mockFetch(200, { id: "a1", hostname: "h" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    const a = await c.getAsset("a1");
    expect(a.hostname).toBe("h");
  });

  it("composes report and returns bytes", async () => {
    const buf = new TextEncoder().encode("%PDF-1.4 fake").buffer;
    const fetchImpl = mockFetch(200, buf, { "Content-Type": "application/pdf" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    const data = await c.composeReport({ preset: "exec_brief", format: "pdf" });
    expect(data.byteLength).toBeGreaterThan(0);
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.preset_id).toBe("exec_brief");
    expect(body.format).toBe("pdf");
  });

  it("generates async report job", async () => {
    const fetchImpl = mockFetch(200, { id: "job_1", status: "queued" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    const job = await c.generateReport("technical_deepdive", "docx");
    expect(job.id).toBe("job_1");
  });

  it("filters findings by severity", async () => {
    const fetchImpl = mockFetch(200, [{ id: "f1", severity: "critical" }]);
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    const f = await c.getFindings({ severity: "critical" });
    expect(f[0].severity).toBe("critical");
    expect(fetchImpl.mock.calls[0][0]).toContain("severity=critical");
  });

  it("lists templates and saves one", async () => {
    const list = mockFetch(200, [{ id: "t1", name: "Exec", sections: [] }]);
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl: list });
    const tpls = await c.listTemplates();
    expect(tpls[0].name).toBe("Exec");

    const save = mockFetch(200, { id: "t9", name: "Board", sections: ["risk_register"] });
    const c2 = new Client({ baseUrl: "https://x.example.com", fetchImpl: save });
    const saved = await c2.saveTemplate("Board", ["risk_register"], { sites: ["nyc"] });
    expect(saved.id).toBe("t9");
    const init = save.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.scope.sites).toEqual(["nyc"]);
  });

  it("throws AuthError on 401", async () => {
    const fetchImpl = mockFetch(401, { detail: "no auth" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    await expect(c.listInventory()).rejects.toBeInstanceOf(AuthError);
  });

  it("throws NotFound on 404", async () => {
    const fetchImpl = mockFetch(404, { detail: "missing" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    await expect(c.getAsset("nope")).rejects.toBeInstanceOf(NotFound);
  });

  it("throws RateLimitError on 429 with retry-after", async () => {
    const fetchImpl = mockFetch(429, { detail: "slow" }, { "Retry-After": "30" });
    const c = new Client({ baseUrl: "https://x.example.com", fetchImpl });
    try {
      await c.listInventory();
      throw new Error("should not reach");
    } catch (err) {
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).retryAfter).toBe(30);
    }
  });
});
