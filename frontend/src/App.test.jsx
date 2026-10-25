import React from "react";
import { readFileSync } from "node:fs";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { applyTheme } from "./theme";
import { beforeEach, describe, it, expect, vi } from "vitest";
import App, { clearAppDataCache } from "./App";
import { api, download, refreshCsrfToken } from "./api";
vi.mock("./api", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
  setCsrfToken: vi.fn(),
  refreshCsrfToken: vi.fn().mockResolvedValue("synthetic-csrf-token"),
  errorMessage: (e) => e.message,
  isCancel: (e) => Boolean(e?.code === "ERR_CANCELED" || e?.name === "CanceledError" || e?.name === "AbortError"),
  download: vi.fn(),
}));
const dashboard = {
  total_scans: 0,
  states: { completed: 0, completed_with_errors: 0, queued: 0, running: 0, failed: 0, cancelled: 0 },
  total_findings: 0,
  severities: {},
  coverage: { selected: 0, executed: 0, successful: 0, failed: 0, timed_out: 0, skipped: 0 },
  recent: [],
};
const profiles = {
  quick: { tools: ["nmap", "httpx", "whatweb"], description: "Five web ports" },
  standard: { tools: ["nmap"], description: "Common ports" },
};
function mockAppGet(
  fallback,
  { initialized = true, sessionError = null, registrationEnabled = true } = {},
) {
  api.get.mockImplementation((path, ...args) => {
    if (path === "/api/auth/status") {
      return Promise.resolve({
        data: {
          data: {
            administrator_initialized: initialized,
            registration_enabled: registrationEnabled,
          },
        },
      });
    }
    if (path === "/api/auth/session") {
      return sessionError
        ? Promise.reject(sessionError)
        : Promise.resolve({ data: { data: { username: "local-admin", csrf_token: "synthetic-csrf-token" } } });
    }
    return fallback(path, ...args);
  });
}
beforeEach(() => {
  vi.clearAllMocks();
  clearAppDataCache();
  mockAppGet((path) =>
    Promise.resolve({ data: { data: path === "/api/dashboard" ? dashboard : path === "/api/profiles" ? profiles : [], meta: { total: 0 } } }),
  );
});
function signOutMock(error = { response: { status: 401 } }) {
  mockAppGet(
    (path) => Promise.resolve({ data: { data: path === "/api/dashboard" ? dashboard : profiles } }),
    { sessionError: error },
  );
}
it("shows the real empty dashboard state and first-assessment action", async () => {
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Assessment overview" })).toBeInTheDocument();
  expect(
    await screen.findByText("Your first assessment starts here"),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Create first assessment/ })).toBeInTheDocument();
});
it("renders tool coverage counts from the dashboard response", async () => {
  const populated = {
    ...dashboard,
    total_scans: 3,
    states: { completed: 1, completed_with_errors: 1, queued: 0, running: 0, failed: 1, cancelled: 0 },
    coverage: { selected: 18, executed: 14, successful: 10, failed: 2, timed_out: 1, skipped: 1 },
  };
  mockAppGet((path) =>
    Promise.resolve({ data: { data: path === "/api/dashboard" ? populated : [] } }),
  );
  render(<App />);
  expect(await screen.findByText("18")).toBeInTheDocument();
  expect(screen.getByText("14")).toBeInTheDocument();
  expect(screen.getByText("10")).toBeInTheDocument();
  expect(screen.getByText("2")).toBeInTheDocument();
  expect(screen.getByText("Timed out")).toBeInTheDocument();
  expect(screen.getByText("Skipped")).toBeInTheDocument();

  const coveragePanel = screen.getByText("Tool execution coverage").closest(".panel");
  const link = coveragePanel.querySelector(".panel-title a.text-link");
  expect(link).toBeInTheDocument();
  expect(link).toHaveAttribute("href", "#/tools");
  expect(link).toHaveTextContent("View tool integrations");
});
it("renders the informational note box with readiness verification notice and proper structure", async () => {
  window.location.hash = "/tools";
  mockAppGet((path) =>
    Promise.resolve({ data: { data: [] } }),
  );
  render(<App />);
  const noteBox = await screen.findByRole("note", { name: "Tool readiness notice" });
  expect(noteBox).toBeInTheDocument();
  expect(noteBox).toHaveTextContent("Readiness verification:");
  expect(noteBox).toHaveTextContent("Wapiti remains disabled by default");
});
it("shows API error states", async () => {
  mockAppGet((path) =>
    Promise.reject(new Error("Backend offline")),
  );
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Backend offline");
});
it("requires authorization, then creates a scan", async () => {
  window.location.hash = "/new";
  api.post.mockResolvedValue({ data: { data: { id: "new-id" } } });
  render(<App />);
  await screen.findByText("Five web ports");
  fireEvent.change(screen.getByLabelText("Target hostname or IP address"), {
    target: { value: "127.0.0.1" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Start assessment" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Confirm authorization",
  );
  fireEvent.click(screen.getByLabelText(/I own this target/));
  fireEvent.click(screen.getByRole("button", { name: "Start assessment" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      "/api/scans",
      expect.objectContaining({ target: "127.0.0.1", authorized: true }),
      expect.objectContaining({ headers: expect.any(Object) }),
    ),
  );
});
it("rejects malformed target inputs with invalid characters or schemes", async () => {
  window.location.hash = "/new";
  render(<App />);
  await screen.findByText("Five web ports");
  fireEvent.change(screen.getByLabelText("Target hostname or IP address"), {
    target: { value: "ftp://example.com" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Start assessment" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Only http:// and https:// URL schemes are supported");
  expect(api.post).not.toHaveBeenCalled();
});

it("accepts valid web endpoint with custom port in assessment form", async () => {
  window.location.hash = "/new";
  render(<App />);
  await screen.findByText("Five web ports");
  fireEvent.change(screen.getByLabelText("Target hostname or IP address"), {
    target: { value: "http://127.0.0.1:3000" },
  });
  fireEvent.click(screen.getByLabelText(/I own this target or have explicit permission/i));
  fireEvent.click(screen.getByRole("button", { name: "Start assessment" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      "/api/scans",
      expect.objectContaining({ target: "http://127.0.0.1:3000", authorized: true }),
      expect.objectContaining({ headers: expect.any(Object) }),
    ),
  );
});
it("shows admin sign-in when the server has no authenticated session", async () => {
  sessionStorage.setItem("ava-token", "obsolete-synthetic-token");
  signOutMock();
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Welcome to PATROLMAN" })).toBeInTheDocument();
  expect(screen.getByText("Sign in to securely access your assessment workspace.")).toBeInTheDocument();
  expect(sessionStorage.getItem("ava-token")).toBeNull();
  expect(screen.getByRole("tab", { name: "Admin Sign Up" })).toBeInTheDocument();
});
it("explains that an older backend must restart before admin login", async () => {
  api.get.mockRejectedValueOnce({ response: { status: 404 } });
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The running backend must be restarted to enable administrator login.",
  );
});
it("shows and hides the password without storing credentials in browser storage", async () => {
  signOutMock();
  render(<App />);
  const input = await screen.findByLabelText("Password");
  expect(input).toHaveAttribute("type", "password");
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "local-admin" } });
  fireEvent.change(input, { target: { value: "synthetic-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Show password" }));
  expect(input).toHaveAttribute("type", "text");
  expect(sessionStorage.length).toBe(0);
  fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
  expect(input).toHaveAttribute("type", "password");
});
it("reports generic credential failures and backend-connection failures", async () => {
  signOutMock();
  api.post.mockRejectedValueOnce({
    response: { status: 401, data: { error: { message: "Unauthorized" } } },
  });
  const { unmount } = render(<App />);
  fireEvent.change(await screen.findByLabelText("Username"), {
    target: { value: "local-admin" },
  });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "synthetic-invalid-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign In" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The username or password was not recognized",
  );
  expect(sessionStorage.length).toBe(0);
  unmount();

  signOutMock();
  api.post.mockRejectedValueOnce(new Error("Network Error"));
  render(<App />);
  fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "local-admin" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "synthetic-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign In" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Cannot connect to the local backend",
  );
  expect(sessionStorage.length).toBe(0);
});
it("establishes a server session and logs out without browser-held credentials", async () => {
  signOutMock();
  api.post
    .mockResolvedValueOnce({ data: { data: { username: "local-admin", csrf_token: "synthetic-csrf-token" } } })
    .mockResolvedValueOnce({ data: {} });
  render(<App />);
  fireEvent.change(await screen.findByLabelText("Username"), {
    target: { value: "local-admin" },
  });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "synthetic-password" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign In" }));
  expect(await screen.findByRole("heading", { name: "Assessment overview" })).toBeInTheDocument();
  expect(refreshCsrfToken).toHaveBeenCalled();
  expect(api.post).toHaveBeenNthCalledWith(1, "/api/auth/login", {
    username: "local-admin",
    password: "synthetic-password",
  });
  expect(sessionStorage.length).toBe(0);
  fireEvent.click(
    screen.getByRole("button", { name: "Disconnect workspace" }),
  );
  expect(api.post).toHaveBeenNthCalledWith(2, "/api/auth/logout");
  expect(
    await screen.findByRole("heading", { name: "Welcome to PATROLMAN" }),
  ).toBeInTheDocument();
});
it("creates the first administrator and establishes a server session", async () => {
  mockAppGet(
    (path) => Promise.resolve({ data: { data: path === "/api/dashboard" ? dashboard : profiles } }),
    { initialized: false },
  );
  api.post.mockResolvedValue({
    data: { data: { username: "first-admin", csrf_token: "synthetic-csrf-token" } },
  });
  render(<App />);
  expect(await screen.findByRole("tab", { name: "Admin Sign Up" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("heading", { name: "Welcome to PATROLMAN" })).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "first-admin" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "strong-synthetic-password-123" } });
  fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "strong-synthetic-password-123" } });
  fireEvent.click(screen.getByRole("button", { name: "Create Admin Account" }));
  expect(await screen.findByRole("heading", { name: "Assessment overview" })).toBeInTheDocument();
  expect(api.post).toHaveBeenCalledWith("/api/auth/signup", {
    username: "first-admin",
    password: "strong-synthetic-password-123",
    confirm_password: "strong-synthetic-password-123",
  });
  expect(sessionStorage.length).toBe(0);
});
it("accepts an eight-character signup password", async () => {
  signOutMock();
  api.post.mockResolvedValue({
    data: { data: { username: "eight-pass", csrf_token: "synthetic-csrf-token" } },
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("tab", { name: "Admin Sign Up" }));
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "eight-pass" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "abcdefgh" } });
  fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "abcdefgh" } });
  fireEvent.click(screen.getByRole("button", { name: "Create Admin Account" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith("/api/auth/signup", {
      username: "eight-pass",
      password: "abcdefgh",
      confirm_password: "abcdefgh",
    }),
  );
});
it("validates signup confirmation before sending a request", async () => {
  mockAppGet(
    (path) => Promise.resolve({ data: { data: path === "/api/dashboard" ? dashboard : profiles } }),
    { initialized: false },
  );
  render(<App />);
  await screen.findByRole("tab", { name: "Admin Sign Up" });
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "first-admin" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "strong-synthetic-password-123" } });
  fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "not-the-same-password-123" } });
  fireEvent.click(screen.getByRole("button", { name: "Create Admin Account" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Passwords do not match");
  expect(api.post).not.toHaveBeenCalled();
});
it("allows an additional administrator to register after initialization", async () => {
  signOutMock();
  api.post.mockResolvedValue({
    data: { data: { username: "second-admin", csrf_token: "synthetic-csrf-token" } },
  });
  render(<App />);
  const signupTab = await screen.findByRole("tab", { name: "Admin Sign Up" });
  expect(signupTab).toHaveAttribute("aria-disabled", "false");
  fireEvent.click(signupTab);
  expect(screen.getByRole("tab", { name: "Admin Login" })).toHaveAttribute("aria-selected", "false");
  expect(screen.getByText(/Create another administrator account/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "second-admin" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "abcdefgh" } });
  fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "abcdefgh" } });
  fireEvent.click(screen.getByRole("button", { name: "Create Admin Account" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith("/api/auth/signup", {
      username: "second-admin",
      password: "abcdefgh",
      confirm_password: "abcdefgh",
    }),
  );
  expect(await screen.findByRole("heading", { name: "Assessment overview" })).toBeInTheDocument();
});
it("rejects a seven-character signup password locally", async () => {
  signOutMock();
  render(<App />);
  fireEvent.click(await screen.findByRole("tab", { name: "Admin Sign Up" }));
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "short-pass" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "abcdefg" } });
  fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "abcdefg" } });
  fireEvent.click(screen.getByRole("button", { name: "Create Admin Account" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("at least 8 characters");
  expect(api.post).not.toHaveBeenCalled();
});
it("hides registration when the server disables it", async () => {
  mockAppGet(
    (path) => Promise.resolve({ data: { data: path === "/api/dashboard" ? dashboard : profiles } }),
    { sessionError: { response: { status: 401 } }, registrationEnabled: false },
  );
  render(<App />);
  const signupTab = await screen.findByRole("tab", { name: "Admin Sign Up" });
  expect(signupTab).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(signupTab);
  expect(screen.getByRole("tab", { name: "Admin Login" })).toHaveAttribute("aria-selected", "true");
});
function scan(state = "running") {
  return {
    id: "scan-test",
    target: "127.0.0.1",
    profile: "quick",
    state,
    configuration: {},
    progress: {
      processed: state === "running" ? 0 : 1,
      total: 1,
      current_tool: state === "running" ? "nmap" : null,
    },
    executions: [
      {
        id: 1,
        tool: "nmap",
        state: state === "running" ? "running" : "completed",
      },
    ],
    findings: [],
    assets: [],
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    ended_at: state === "running" ? null : new Date().toISOString(),
  };
}
it("updates live monitor from running to completed", async () => {
  window.location.hash = "/scan/scan-test";
  let calls = 0;
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings")
          ? []
          : scan(++calls > 1 ? "completed" : "running"),
        meta: { total: 0 },
      },
    }),
  );
  render(<App />);
  expect(await screen.findByText("Running nmap")).toBeInTheDocument();
  expect(
    await screen.findByText(
      "Review coverage and evidence",
      {},
      { timeout: 2500 },
    ),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "HTML report" }),
  ).toBeInTheDocument();
});
it("handles transient network error during scan polling without flashing banner", async () => {
  window.location.hash = "/scan/scan-transient-test";
  let calls = 0;
  mockAppGet((path) => {
    if (path.includes("/findings")) {
      return Promise.resolve({ data: { data: [], meta: { total: 0 } } });
    }
    calls++;
    if (calls === 1) {
      return Promise.resolve({ data: { data: scan("running"), meta: { total: 0 } } });
    }
    if (calls === 2) {
      const err = new Error("Network Error");
      err.code = "ERR_NETWORK";
      return Promise.reject(err);
    }
    return Promise.resolve({ data: { data: scan("completed"), meta: { total: 0 } } });
  });
  render(<App />);
  expect(await screen.findByText("Running nmap")).toBeInTheDocument();
  // With transient smoothing, the single failure does not display a false-alarm banner
  expect(screen.queryByText("Network Error")).not.toBeInTheDocument();
  expect(
    await screen.findByText(
      "Review coverage and evidence",
      {},
      { timeout: 3000 },
    ),
  ).toBeInTheDocument();
  expect(screen.queryByText("Network Error")).not.toBeInTheDocument();
});
it("displays persistent network errors when consecutive polling requests fail", async () => {
  window.location.hash = "/scan/scan-persistent-test";
  let calls = 0;
  mockAppGet((path) => {
    if (path.includes("/findings")) {
      return Promise.resolve({ data: { data: [], meta: { total: 0 } } });
    }
    calls++;
    if (calls === 1) {
      return Promise.resolve({ data: { data: scan("running"), meta: { total: 0 } } });
    }
    const err = new Error("Network Error");
    err.code = "ERR_NETWORK";
    return Promise.reject(err);
  });
  render(<App />);
  expect(await screen.findByText("Running nmap")).toBeInTheDocument();
  // Consecutive failures must surface as a persistent error banner
  expect(await screen.findByText("Network Error", {}, { timeout: 3500 })).toBeInTheDocument();
});
it("displays error banner immediately on initial load failure when no data exists", async () => {
  window.location.hash = "/scan/scan-nonexistent";
  mockAppGet(() => {
    const err = new Error("Scan not found");
    err.response = { status: 404, data: { error: { message: "Scan not found" } } };
    return Promise.reject(err);
  });
  render(<App />);
  expect(await screen.findByText("Scan not found")).toBeInTheDocument();
});
it("starts the selected authenticated report download", async () => {
  window.location.hash = "/scan/scan-test";
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings") ? [] : scan("completed"),
        meta: { total: 0 },
      },
    }),
  );
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "HTML report" }));
  await waitFor(() => expect(download).toHaveBeenCalledWith("scan-test", "html"));
});
it("loads saved assessment history and compares completed scans", async () => {
  window.location.hash = "/history";
  const scans = ["first-scan", "second-scan"].map((id) => ({
    id,
    target: "127.0.0.1",
    profile: "quick",
    state: "completed",
    finding_count: 0,
    created_at: new Date().toISOString(),
  }));
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data:
          path === "/api/scans/compare"
            ? { new: [], resolved_candidates: [], unchanged: [], warning: "Review" }
            : path.startsWith("/api/scans?")
              ? scans
              : path === "/api/dashboard"
                ? dashboard
                : profiles,
        meta: { total: scans.length },
      },
    }),
  );
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Scan history" })).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("First scan"), {
    target: { value: "first-scan" },
  });
  fireEvent.change(screen.getByLabelText("Second scan"), {
    target: { value: "second-scan" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Compare" }));
  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/api/scans/compare", {
      params: { first: "first-scan", second: "second-scan" },
    }),
  );
  expect(await screen.findByText("Review")).toBeInTheDocument();
});
it("renders finding evidence and remediation", async () => {
  window.location.hash = "/scan/scan-test";
  const finding = {
    id: 1,
    title: "Missing response header",
    severity: "informational",
    details: {
      target: "http://127.0.0.1:8000",
      sources: [{ tool: "nuclei" }],
      remediation: "Configure nosniff.",
      risk_reason: "Scanner severity mapping.",
      evidence: "Header absent",
    },
  };
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings")
          ? [finding]
          : { ...scan("completed"), findings: [finding] },
        meta: { total: 1 },
      },
    }),
  );
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: /Missing response header/ }),
  );
  expect(screen.getByRole("dialog")).toHaveTextContent("Configure nosniff.");
  expect(screen.getByRole("dialog")).toHaveTextContent("Header absent");
});
it("sends the cancellation request", async () => {
  window.location.hash = "/scan/scan-test";
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings") ? [] : scan(),
        meta: { total: 0 },
      },
    }),
  );
  api.post.mockResolvedValue({
    data: { data: { cancellation_requested: true } },
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Cancel scan" }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith("/api/scans/scan-test/cancel"),
  );
});
describe("theme", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.matchMedia = vi.fn().mockReturnValue({ matches: false });
  });
  it("toggles the workspace theme and persists the choice", async () => {
    render(<App />);
    const toggle = await screen.findByRole("button", {
      name: "Switch to dark theme",
    });
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    fireEvent.click(toggle);
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem("ava-theme")).toBe("dark");
    fireEvent.click(
      screen.getByRole("button", { name: "Switch to light theme" }),
    );
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(window.localStorage.getItem("ava-theme")).toBe("light");
  });
  it("ensures theme toggle is absent from the sign-in view", async () => {
    api.get.mockRejectedValueOnce({ response: { status: 401 } });
    render(<App />);
    await screen.findByRole("button", { name: "Sign In" });
    expect(
      screen.queryByRole("button", { name: /switch to (dark|light) theme/i }),
    ).toBeNull();
  });
  it("restores a stored preference without waiting for an interaction", async () => {
    window.localStorage.setItem("ava-theme", "dark");
    render(<App />);
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(
      await screen.findByRole("button", { name: "Switch to light theme" }),
    ).toBeInTheDocument();
  });
  it("falls back to the system preference when nothing is stored", async () => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: true });
    render(<App />);
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem("ava-theme")).toBeNull();
    expect(
      await screen.findByRole("button", { name: "Switch to light theme" }),
    ).toBeInTheDocument();
  });
  it("keeps the topbar toggle out of the container mobile CSS hides", async () => {
    render(<App />);
    await screen.findByRole("button", { name: /Switch to (dark|light) theme/ });
    // `.local` is display:none below 760px, so nesting the toggle there would
    // make the theme unreachable on a phone.
    expect(document.querySelector(".theme-toggle")).toBeTruthy();
    expect(document.querySelector(".local .theme-toggle")).toBeNull();
  });
  it("applies the stored theme before the app bundle runs (no flash)", () => {
    // vitest root is the frontend directory
    const html = readFileSync("index.html", "utf8");
    const bootstrap = readFileSync("public/theme-init.js", "utf8");
    const script = html.indexOf('<script src="/theme-init.js"></script>');
    const bundle = html.indexOf("<script type=\"module\"");
    expect(script).toBeGreaterThan(-1);
    expect(bundle).toBeGreaterThan(-1);
    expect(script).toBeLessThan(bundle);
    expect(bootstrap).toContain('localStorage.getItem("ava-theme")');
    expect(bootstrap).toContain("data-theme");
    // Inline scripts would require loosening the production CSP.
    expect(html).not.toMatch(/<script>\s/);
  });
  it("keeps the browser chrome colour in step with the chosen theme", () => {
    const meta = document.createElement("meta");
    meta.setAttribute("name", "theme-color");
    document.head.appendChild(meta);
    applyTheme("dark");
    expect(meta.getAttribute("content")).toBe("#121212");
    applyTheme("light");
    expect(meta.getAttribute("content")).toBe("#f5f7f6");
  });
});

it("submits an authorized local directory through the Local profile", async () => {
  window.location.hash = "/new";
  const allProfiles = {...profiles, local: {tools:["gitleaks","trivy"], description:"Local files only"}};
  mockAppGet(path => Promise.resolve({data:{data:path === "/api/profiles" ? allProfiles : []}}));
  api.post.mockResolvedValue({data:{data:{id:"local-id"}}});
  render(<App />);
  fireEvent.click(await screen.findByRole("button", {name:/local Local files only/i}));
  fireEvent.change(screen.getByLabelText(/Authorized local directory/), {target:{value:"C:\\Projects\\My App"}});
  fireEvent.click(screen.getByLabelText(/I own this target/));
  fireEvent.click(screen.getByRole("button",{name:"Start assessment"}));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith("/api/scans", expect.objectContaining({profile:"local", target:"C:\\Projects\\My App",tools:["gitleaks","trivy"]}),expect.any(Object)));
});

it("renders configuration status and purpose for all nine tools", async () => {
  window.location.hash = "/tools";
  const names=["nmap","whatweb","httpx","subfinder","nuclei","wapiti","gitleaks","trivy","sslyze"];
  mockAppGet(() => Promise.resolve({data:{data:names.map(name=>({name,status:"configuration_required",purpose:"Purpose of "+name,reason:"Configure approved scope",setup:"Use official Windows tools"}))}}));
  render(<App />);
  expect(await screen.findByRole("heading",{name:"sslyze"})).toBeInTheDocument();
  for(const name of names) expect(screen.getByText("Purpose of "+name)).toBeInTheDocument();
  expect(screen.getAllByText("CONFIGURATION REQUIRED")).toHaveLength(9);
});

it("renders confirmed, unconfirmed and unknown tool states distinctly", async () => {
  window.location.hash = "/tools";
  mockAppGet(() => Promise.resolve({data:{data:[
    {name:"httpx",status:"blocked",state:"BLOCKED_BY_POLICY",purpose:"Probe",reason:"Windows policy message in stderr."},
    {name:"nmap",status:"execution_blocked",state:"EXECUTION_BLOCKED",purpose:"Discovery",reason:"Windows refused to launch the executable (error 5); evidence is insufficient to confirm a policy block."},
    {name:"nuclei",status:"unknown",state:"UNKNOWN",purpose:"Checks",reason:"Version probe timed out after 5 seconds; readiness unknown."},
  ]}}));
  render(<App />);
  expect(await screen.findByText("BLOCKED BY POLICY")).toBeInTheDocument();
  expect(screen.getByText("EXECUTION BLOCKED")).toBeInTheDocument();
  expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  expect(document.querySelector(".badge.blocked")).toBeInTheDocument();
  expect(document.querySelector(".badge.execution_blocked")).toBeInTheDocument();
  expect(document.querySelector(".badge.unknown")).toBeInTheDocument();
});

it("filters real tool statuses and expands setup details", async () => {
  window.location.hash = "/tools";
  mockAppGet(() => Promise.resolve({data:{data:[
    {
      name:"nmap",status:"ready",state:"READY",executable_found:true,version:"Nmap 7.80",
      purpose:"Bounded local discovery",reason:"Verified by a local assessment.",
      runtime_configuration:{status:"configured",message:"No additional runtime configuration."},
      workflow_verification:{status:"verified",last_state:"completed",last_checked_at:"2025-01-01T00:00:00Z"},
    },
    {
      name:"httpx",status:"configuration_required",executable_found:true,
      purpose:"HTTP probing",reason:"Provider configuration is required.",
      runtime_configuration:{status:"configuration_required",message:"Configure approved runtime settings."},
      setup:"Approved setup instructions for httpx.",
    },
    {
      name:"whatweb",status:"missing",executable_found:false,
      purpose:"Technology fingerprinting",reason:"Backend could not resolve the script.",
    },
    {
      name:"subfinder",status:"blocked",state:"BLOCKED_BY_POLICY",executable_found:true,
      purpose:"Passive inventory",reason:"Execution blocked by policy.",
    },
    {
      name:"nuclei",status:"unverified",executable_found:true,
      purpose:"Reviewed template checks",reason:"Latest workflow failed.",
      workflow_verification:{status:"failed",last_state:"failed"},
    },
    {
      name:"trivy",status:"ready",state:"READY",executable_found:true,
      purpose:"Local dependency checks",version:"Trivy 0.59",
      reason:"Executable identity verified.",
    },
  ]}}));
  render(<App />);
  expect(await screen.findByRole("heading",{name:"nmap"})).toBeInTheDocument();
  expect(screen.getAllByText("Found by backend")).toHaveLength(5);
  expect(screen.getByText("Verified in assessment")).toBeInTheDocument();
  expect(screen.getByText("NEEDS VERIFICATION")).toBeInTheDocument();
  expect(screen.getByText("VERIFICATION FAILED")).toBeInTheDocument();
  expect(screen.getAllByText("Provider configuration is required.")).toHaveLength(2);
  expect(screen.queryByText("The executable is discoverable, but required runtime configuration is missing.")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button",{name:/Not installed/}));
  expect(screen.getByRole("heading",{name:"whatweb"})).toBeInTheDocument();
  expect(screen.queryByRole("heading",{name:"nmap"})).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button",{name:/All/}));
  const httpxCard = screen.getByRole("heading",{name:"httpx"}).closest(".tool-card");
  fireEvent.click(httpxCard.querySelector("summary"));
  expect(screen.getByText("Approved setup instructions for httpx.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button",{name:"Check availability"}));
  await waitFor(() =>
    // Phase 1 (fast): /api/tools?check_versions=false called on mount.
    // Phase 2 (full): /api/tools (check_versions=true) called by button click.
    expect(api.get.mock.calls.filter(([path]) => path === "/api/tools")).toHaveLength(1),
  );
});

it("shows the Wapiti integration status, version and supported capabilities", async () => {
  window.location.hash = "/tools";
  mockAppGet(() => Promise.resolve({data:{data:[{
    name:"wapiti",status:"ready",state:"READY",executable_found:true,version:"3.3.2",
    purpose:"Bounded web vulnerability assessment with an explicit module list (safety gated).",
    reason:"A successful assessment execution and result parsing record exists for this version.",
    runtime_configuration:{status:"configured",message:"Conservative response-inspection modules only (http_headers, cookieflags, csp, methods); no injection module is enabled."},
    operator_opt_in:{status:"enabled",variable:"AVA_WAPITI_ENABLED",message:"Explicit operator opt-in is enabled for this tool."},
    capabilities:["Installation and version verification","Security header, cookie flag, CSP and HTTP method checks by default"],
    safety_restrictions:"Only a literal IP base URL that PATROLMAN already resolved is accepted.",
    setup:"Install Wapiti 3 and set AVA_WAPITI_ENABLED=true.",
    workflow_verification:{status:"verified",last_state:"completed",last_checked_at:"2026-10-20T10:00:00Z"},
  }]}}));
  render(<App />);
  expect(await screen.findByRole("heading",{name:"wapiti"})).toBeInTheDocument();
  expect(screen.getByText("READY")).toBeInTheDocument();
  expect(screen.getByText(/3\.3\.2/)).toBeInTheDocument();
  const capabilities = screen.getByRole("list",{name:"wapiti capabilities"});
  expect(capabilities.querySelectorAll("li")).toHaveLength(2);
  expect(screen.getByText("Security header, cookie flag, CSP and HTTP method checks by default")).toBeInTheDocument();
  expect(screen.getByText("Verified in assessment")).toBeInTheDocument();
  const card = screen.getByRole("heading",{name:"wapiti"}).closest(".tool-card");
  fireEvent.click(card.querySelector("summary"));
  expect(screen.getByText(/Variable: AVA_WAPITI_ENABLED/)).toBeInTheDocument();
  expect(screen.getByText(/literal IP base URL/)).toBeInTheDocument();
  expect(screen.getByText(/Install Wapiti 3/)).toBeInTheDocument();
});

it("reports Wapiti as safety disabled with actionable setup and no false readiness", async () => {
  window.location.hash = "/tools";
  mockAppGet(() => Promise.resolve({data:{data:[{
    name:"wapiti",status:"disabled",state:"DISABLED_FOR_SAFETY",executable_found:true,version:"3.3.2",
    purpose:"Bounded web vulnerability assessment with an explicit module list (safety gated).",
    reason:"Wapiti is safety-disabled until the operator explicitly sets AVA_WAPITI_ENABLED=true.",
    runtime_configuration:{status:"configured",message:"Conservative response-inspection modules only."},
    operator_opt_in:{status:"disabled",variable:"AVA_WAPITI_ENABLED",message:"Explicit operator opt-in is required and is not set, so this tool stays disabled regardless of installation or configuration."},
    capabilities:["Installation and version verification"],
    setup:"Install Wapiti 3 and set AVA_WAPITI_ENABLED=true.",
  }]}}));
  render(<App />);
  expect(await screen.findByRole("heading",{name:"wapiti"})).toBeInTheDocument();
  expect(screen.getByText("SAFETY DISABLED")).toBeInTheDocument();
  expect(screen.getByText(/3\.3\.2/)).toBeInTheDocument();
  expect(screen.queryByText("READY")).not.toBeInTheDocument();
  const card = screen.getByRole("heading",{name:"wapiti"}).closest(".tool-card");
  fireEvent.click(card.querySelector("summary"));
  expect(screen.getByText(/Variable: AVA_WAPITI_ENABLED/)).toBeInTheDocument();
  expect(screen.getByText(/operator opt-in is required/i)).toBeInTheDocument();
  expect(screen.getByText(/Install Wapiti 3/)).toBeInTheDocument();
});

it("offers no manual scanner probe action after the daemon preflight was removed", async () => {
  window.location.hash = "/tools";
  mockAppGet(() => Promise.resolve({data:{data:[{
    name:"wapiti",status:"configuration_required",executable_found:true,
    purpose:"Bounded web vulnerability assessment",reason:"Configure the module list.",
    setup:"Set AVA_WAPITI_ENABLED=true.",
  }]}}));
  render(<App />);
  expect(await screen.findByRole("heading",{name:"wapiti"})).toBeInTheDocument();
  expect(screen.queryByRole("button",{name:/preflight/i})).not.toBeInTheDocument();
  expect(screen.queryByText(/Daemon preflight/)).not.toBeInTheDocument();
});

it("distinguishes completed without findings from a timed out tool", async () => {
  window.location.hash="/scan/scan-test";
  const data={...scan("completed_with_errors"),executions:[
    {id:1,tool:"gitleaks",state:"completed",outcome:"COMPLETED_WITHOUT_FINDINGS",version:"8.30.1"},
    {id:2,tool:"trivy",state:"timed_out",outcome:"TIMED_OUT",error:"Assessment did not finish"}]};
  mockAppGet(path=>Promise.resolve({data:{data:path.includes("/findings")?[]:data,meta:{total:0}}}));
  render(<App />);
  expect(await screen.findByText("COMPLETED WITHOUT FINDINGS")).toBeInTheDocument();
  expect(screen.getByText("TIMED OUT")).toBeInTheDocument();
  expect(screen.getByText("Assessment did not finish")).toBeInTheDocument();
});

it("navigates to Settings page when Settings sidebar item is clicked", async () => {
  window.location.hash = "/";
  render(<App />);
  const settingsLink = await screen.findByRole("link", { name: /Settings/ });
  fireEvent.click(settingsLink);
  expect(await screen.findByRole("heading", { name: "Settings & preferences" })).toBeInTheDocument();
  expect(screen.getByText("Appearance & Display")).toBeInTheDocument();
  expect(screen.getByText("Session & Security")).toBeInTheDocument();
});

it("navigates to Help & documentation page when Help sidebar item is clicked", async () => {
  window.location.hash = "/";
  render(<App />);
  const helpLink = await screen.findByRole("link", { name: /Help & documentation/ });
  fireEvent.click(helpLink);
  expect(await screen.findByRole("heading", { name: "Help & documentation" })).toBeInTheDocument();
  expect(screen.getByText("Assessment Pipeline Architecture")).toBeInTheDocument();
});

it("toggles ProfileMenu dropdown and executes logout", async () => {
  window.location.hash = "/";
  render(<App />);
  const avatarBtn = await screen.findByRole("button", { name: "User account menu" });
  fireEvent.click(avatarBtn);
  const menu = screen.getByRole("menu", { name: "Account options" });
  expect(menu).toBeInTheDocument();
  expect(within(menu).getByText("Settings & preferences")).toBeInTheDocument();
  expect(within(menu).getByText("Help & documentation")).toBeInTheDocument();
  const logoutBtn = within(menu).getByRole("menuitem", { name: /Log out/i });
  fireEvent.click(logoutBtn);
  await waitFor(() => {
    expect(api.post).toHaveBeenCalledWith("/api/auth/logout");
  });
});

it("accepts search query in GlobalSearch and displays matching results", async () => {
  window.location.hash = "/";
  render(<App />);
  const searchInput = await screen.findByPlaceholderText("Search scans, targets, or tools...");
  fireEvent.change(searchInput, { target: { value: "nmap" } });
  expect(await screen.findByRole("listbox")).toBeInTheDocument();
  expect(screen.getByText("Network discovery & port scanning")).toBeInTheDocument();
});

it("renders Refresh data button in the dashboard header and calls reload", async () => {
  window.location.hash = "/";
  render(<App />);
  const refreshBtn = await screen.findByRole("button", { name: /Refresh data/ });
  expect(refreshBtn).toBeInTheDocument();
  fireEvent.click(refreshBtn);
  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith("/api/dashboard", expect.anything());
  });
});

it("renders tool-status badges with semantic classes and icons without false green reassurance", async () => {
  window.location.hash = "/scan/scan-badges-test";
  const data = {
    ...scan("completed"),
    executions: [
      { id: 1, tool: "gitleaks", state: "completed", outcome: "COMPLETED_WITHOUT_FINDINGS", version: "8.30.1" },
      { id: 2, tool: "nuclei", state: "completed", outcome: "COMPLETED_WITH_FINDINGS", version: "3.3.7" },
      { id: 3, tool: "wapiti", state: "skipped", outcome: "DISABLED_FOR_SAFETY", error: "Safety disabled" },
      { id: 4, tool: "testssl", state: "failed", outcome: "FAILED", error: "Execution error" },
      { id: 5, tool: "nmap", state: "running", outcome: "RUNNING" },
    ],
  };
  mockAppGet((path) =>
    Promise.resolve({ data: { data: path.includes("/findings") ? [] : data, meta: { total: 0 } } })
  );
  render(<App />);

  // Neutral blue/grey styling for COMPLETED_WITHOUT_FINDINGS
  const noFindingsBadge = await screen.findByText("COMPLETED WITHOUT FINDINGS");
  expect(noFindingsBadge.closest(".badge")).toHaveClass("completed_without_findings");

  // Amber styling for COMPLETED_WITH_FINDINGS
  const withFindingsBadge = screen.getByText("COMPLETED WITH FINDINGS");
  expect(withFindingsBadge.closest(".badge")).toHaveClass("completed_with_findings");

  // Neutral grey styling for DISABLED_FOR_SAFETY
  const skippedBadge = screen.getByText("DISABLED FOR SAFETY");
  expect(skippedBadge.closest(".badge")).toHaveClass("disabled_for_safety");

  // Red styling for FAILED
  const failedBadge = screen.getByText("FAILED");
  expect(failedBadge.closest(".badge")).toHaveClass("failed");

  // Tool details notes display skip reason and failure details
  expect(screen.getByText("Safety disabled")).toBeInTheDocument();
  expect(screen.getByText("Execution error")).toBeInTheDocument();
  expect(screen.getByText("Execution completed; potential findings recorded for review.")).toBeInTheDocument();
  expect(screen.getByText("Execution completed; no findings detected by this scanner.")).toBeInTheDocument();
});

it("renders finding details modal with structured sections, explicit scanner-reported confidence, and CVSS not assessed fallback", async () => {
  window.location.hash = "/scan/scan-finding-modal-test";
  const findingA = {
    id: "f-dir-list",
    title: "Directory Listing Enabled",
    severity: "medium",
    first_seen: new Date().toISOString(),
    details: {
      target: "http://127.0.0.1:3000/ftp/",
      description: "Directory listing was detected on the target server, exposing file paths and sensitive resources.",
      remediation: "Disable directory listing in the web server configuration.",
      risk_reason: "Severity mapping from scanner; no validated CVSS score available.",
      status: "potential",
      confidence: "scanner-reported",
      cvss_score: null,
      classification: { "cwe-id": ["cwe-548"] },
      sources: [{ tool: "nuclei", identifier: "exposed-directory-listing" }],
      evidence: {
        curl_command: "curl -X 'GET' -d '' -H 'Accept: */*' 'http://127.0.0.1:3000/ftp/'",
        request: "GET /ftp/ HTTP/1.1\nHost: 127.0.0.1:3000",
      },
    },
  };
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings") ? [findingA] : scan("completed"),
        meta: { total: 1 },
      },
    })
  );
  render(<App />);

  // Open modal by clicking finding link
  const link = await screen.findByRole("button", { name: /Directory Listing Enabled/i });
  fireEvent.click(link);

  // Modal dialog is opened
  const modal = screen.getByRole("dialog", { name: "Finding details" });
  expect(modal).toBeInTheDocument();

  // Separate Severity, Status, and Confidence fields
  expect(within(modal).getByText(/Severity:\s*medium/i)).toBeInTheDocument();
  expect(within(modal).getByText("Status: Potential (manual validation required)")).toBeInTheDocument();
  expect(within(modal).getByText("Confidence: scanner-reported")).toBeInTheDocument();

  // Missing CVSS displays "CVSS not assessed"
  expect(within(modal).getByText("CVSS not assessed")).toBeInTheDocument();

  // Affected endpoint
  expect(within(modal).getByText("http://127.0.0.1:3000/ftp/")).toBeInTheDocument();

  // Summary, description & remediation
  expect(within(modal).getByText(/Directory listing was detected on the target server/, { selector: ".finding-description" })).toBeInTheDocument();
  expect(within(modal).getByText(/Disable directory listing in the web server configuration/, { selector: ".remediation-text" })).toBeInTheDocument();

  // Clean reproduction command formatted as curl -i
  expect(within(modal).getByText('curl -i "http://127.0.0.1:3000/ftp/"')).toBeInTheDocument();

  // Copy button exists
  expect(within(modal).getByRole("button", { name: "Copy reproduction command" })).toBeInTheDocument();

  // Classification link
  const cweLink = within(modal).getByRole("link", { name: /CWE-548/i });
  expect(cweLink).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/548.html");

  // Collapsible raw technical evidence
  expect(within(modal).getByText("Raw technical evidence & scanner output")).toBeInTheDocument();
});

it("copies reproduction command and provides copied confirmation in finding details modal", async () => {
  window.location.hash = "/scan/scan-copy-repro-test";
  const findingB = {
    id: "f-app-config",
    title: "Application Configuration Exposure",
    severity: "medium",
    first_seen: new Date().toISOString(),
    details: {
      target: "http://127.0.0.1:3000/rest/admin/application-configuration",
      description: "Disclosing internal application settings.",
      status: "potential",
      confidence: "scanner-reported",
      cvss_score: null,
      evidence: {
        curl_command: "curl -X 'GET' -d '' 'http://127.0.0.1:3000/rest/admin/application-configuration'",
      },
    },
  };
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings") ? [findingB] : scan("completed"),
        meta: { total: 1 },
      },
    })
  );
  render(<App />);

  const link = await screen.findByRole("button", { name: /Application Configuration Exposure/i });
  fireEvent.click(link);

  const copyBtn = screen.getByRole("button", { name: "Copy reproduction command" });
  expect(copyBtn).toHaveTextContent("Copy command");

  fireEvent.click(copyBtn);
  expect(copyBtn).toHaveTextContent("Copied!");
});

it("renders validated CVSS score and vector when present", async () => {
  window.location.hash = "/scan/scan-cvss-test";
  const findingWithCvss = {
    id: "f-cvss",
    title: "SQL Injection in Search",
    severity: "high",
    first_seen: new Date().toISOString(),
    details: {
      target: "http://127.0.0.1:3000/rest/products/search",
      description: "SQL injection vulnerability.",
      status: "confirmed",
      confidence: "scanner-reported",
      cvss_score: 8.5,
      cvss_version: "3.1",
      classification: { "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" },
    },
  };
  mockAppGet((path) =>
    Promise.resolve({
      data: {
        data: path.includes("/findings") ? [findingWithCvss] : scan("completed"),
        meta: { total: 1 },
      },
    })
  );
  render(<App />);

  const link = await screen.findByRole("button", { name: /SQL Injection in Search/i });
  fireEvent.click(link);

  expect(screen.getByText("CVSS 8.5 (v3.1)")).toBeInTheDocument();
  expect(screen.queryByText("CVSS not assessed")).not.toBeInTheDocument();
  expect(screen.getByText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")).toBeInTheDocument();
  expect(screen.getByText("Status: Confirmed (evidence verified)")).toBeInTheDocument();
});
