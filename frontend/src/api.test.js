import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { api, refreshCsrfToken, setCsrfToken } from "./api";

describe("session API client", () => {
  const originalAdapter = api.defaults.adapter;

  afterEach(() => {
    setCsrfToken("");
    api.defaults.adapter = originalAdapter;
  });

  it("fetches the pre-session CSRF token and sends it on the next request", async () => {
    const sent = [];
    api.defaults.adapter = async (config) => {
      sent.push(config);
      return {
        config,
        data:
          config.url === "/api/auth/csrf"
            ? { data: { csrf_token: "bootstrap-csrf-value" } }
            : {},
        headers: {},
        status: 200,
        statusText: "OK",
      };
    };
    expect(await refreshCsrfToken()).toBe("bootstrap-csrf-value");
    await api.post("/api/auth/login", {});
    expect(sent[0].url).toBe("/api/auth/csrf");
    expect(sent[0].withCredentials).toBe(true);
    expect(sent[0].headers.get("X-CSRF-Token")).toBeUndefined();
    expect(sent[1].headers.get("X-CSRF-Token")).toBe("bootstrap-csrf-value");
  });

  it("sends the in-memory CSRF header with state-changing requests and no bearer token", async () => {
    let sent;
    api.defaults.adapter = async (config) => {
      sent = config;
      return {
        config,
        data: {},
        headers: {},
        status: 200,
        statusText: "OK",
      };
    };
    setCsrfToken("synthetic-csrf-value");
    await api.post("/api/auth/logout");
    expect(sent.headers.get("X-CSRF-Token")).toBe("synthetic-csrf-value");
    expect(sent.headers.get("Authorization")).toBeUndefined();
    expect(sent.withCredentials).toBe(true);
  });

  it("keeps the dev proxy host unchanged so origin validation matches", () => {
    // Read the config as text: importing it pulls esbuild/plugins into jsdom.
    const config = readFileSync("vite.config.js", "utf8");
    // Development still targets the local backend; the end-to-end auth test
    // overrides the target for its throwaway Vite instance via the env hook.
    expect(config).toContain('process.env.AVA_PROXY_TARGET || "http://127.0.0.1:5055"');
    expect(config).toContain("changeOrigin: false");
    // The string shorthand sets changeOrigin: true and caused the 403.
    expect(config).not.toMatch(/"\/api":\s*"http/);
  });

  it("does not send CSRF tokens with safe GET requests", async () => {
    let sent;
    api.defaults.adapter = async (config) => {
      sent = config;
      return { config, data: {}, headers: {}, status: 200, statusText: "OK" };
    };
    setCsrfToken("synthetic-csrf-value");
    await api.get("/api/auth/session");
    expect(sent.headers.get("X-CSRF-Token")).toBeUndefined();
  });

  it("identifies canceled and aborted requests accurately", async () => {
    const { isCancel } = await import("./api");
    expect(isCancel({ code: "ERR_CANCELED" })).toBe(true);
    expect(isCancel({ name: "CanceledError" })).toBe(true);
    expect(isCancel({ name: "AbortError" })).toBe(true);
    expect(isCancel(new Error("Network Error"))).toBe(false);
    expect(isCancel(null)).toBe(false);
  });
});
