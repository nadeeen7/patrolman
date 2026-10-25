import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { beforeEach, describe, it, expect, vi } from "vitest";
import App from "./App";
import { api } from "./api";

vi.mock("./api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  setCsrfToken: vi.fn(),
  refreshCsrfToken: vi.fn().mockResolvedValue("synthetic-csrf-token"),
  errorMessage: (e) => e.message,
  download: vi.fn(),
}));

const mockTargets = [
  {
    id: "target-1234",
    name: "Corporate Web App",
    target_type: "organization",
    owner_organization: "ACME Corp",
    scope_domains: ["example.com", "127.0.0.1"],
    explicit_subdomains: ["api.example.com"],
    excluded_scope: ["/admin/billing"],
    permitted_methods: ["port_scan", "tls_audit"],
    prohibited_methods: ["dos", "exploit"],
    rate_limit_rps: 10,
    valid_from: "2026-01-01T00:00:00Z",
    valid_to: "2026-12-31T23:59:59Z",
    evidence_reference: "Board Authorization 2026",
    status: "active",
    effective_status: "active",
    created_by: "security_admin",
    updated_by: "security_admin",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    audit_events: [
      {
        id: 1,
        target_id: "target-1234",
        event_type: "created",
        actor: "security_admin",
        details: { name: "Corporate Web App" },
        created_at: "2026-01-01T00:00:00Z",
      },
    ],
  },
];

function mockAppGet(targets = mockTargets, scopeImports = { data: { data: [] } }) {
  api.get.mockImplementation((path) => {
    if (path === "/api/auth/status") {
      return Promise.resolve({ data: { data: { administrator_initialized: true } } });
    }
    if (path === "/api/auth/session") {
      return Promise.resolve({ data: { data: { username: "local-admin", csrf_token: "csrf-token" } } });
    }
    if (path === "/api/profiles") {
      return Promise.resolve({
        data: {
          data: {
            quick: { tools: ["nmap", "httpx", "whatweb"], description: "Quick scan" },
            standard: { tools: ["nmap", "httpx", "whatweb", "nuclei"], description: "Standard scan" },
          },
          meta: {},
        },
      });
    }
    if (path === "/api/tools") {
      return Promise.resolve({
        data: {
          data: [
            { name: "nmap", status: "ready" },
            { name: "httpx", status: "ready" },
            { name: "whatweb", status: "ready" },
            { name: "nuclei", status: "ready" },
          ],
          meta: {},
        },
      });
    }
    if (path === "/api/targets/target-1234/scope-imports") {
      if (scopeImports instanceof Error) {
        return Promise.reject(scopeImports);
      }
      return Promise.resolve(scopeImports);
    }
    if (path.startsWith("/api/targets/target-1234")) {
      return Promise.resolve({ data: { data: targets[0] } });
    }
    if (path.startsWith("/api/targets")) {
      return Promise.resolve({
        data: {
          data: targets,
          meta: {
            page: 1,
            page_size: 20,
            total: targets.length,
            metrics: {
              total: targets.length,
              active: targets.filter((t) => t.effective_status === "active").length,
              expired: targets.filter((t) => t.effective_status === "expired").length,
              revoked: targets.filter((t) => t.effective_status === "revoked").length,
              inactive: targets.filter((t) => t.effective_status === "inactive").length,
            },
          },
        },
      });
    }
    return Promise.resolve({ data: { data: [], meta: { total: 0 } } });
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  window.location.hash = "#/targets";
});

describe("Authorized Targets Management", () => {
  it("renders the navigation item and page heading", async () => {
    mockAppGet([]);
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Authorized targets" })).toBeInTheDocument();
    expect(screen.getByText("AUTHORIZED SCOPE & TARGETS")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Register target/i })).toBeInTheDocument();
    expect(await screen.findByText("No registered authorized targets")).toBeInTheDocument();
  });

  it("displays metric cards and registered targets list", async () => {
    mockAppGet();
    render(<App />);

    expect(await screen.findByText("Corporate Web App")).toBeInTheDocument();
    expect(screen.getByText("ACME Corp")).toBeInTheDocument();
    expect(screen.getByText("example.com, 127.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();

    // Metrics cards
    expect(screen.getByText("Total targets")).toBeInTheDocument();
    expect(screen.getByText("Active (in scope)")).toBeInTheDocument();
  });

  it("opens register target modal and handles submission", async () => {
    mockAppGet();
    api.post.mockResolvedValueOnce({
      data: { data: { id: "target-5678", name: "New Client Target" } },
    });

    render(<App />);
    const registerBtn = await screen.findByRole("button", { name: /Register target/i });
    fireEvent.click(registerBtn);

    expect(screen.getByRole("dialog", { name: "Register authorized target" })).toBeInTheDocument();

    // Fill form
    fireEvent.change(screen.getByLabelText("Target friendly name"), {
      target: { value: "New Client Portal" },
    });
    fireEvent.change(screen.getByLabelText("Target owner or organization"), {
      target: { value: "Client Corp" },
    });
    fireEvent.change(
      screen.getByLabelText(/In-scope domains and IP addresses/),
      { target: { value: "client.com" } }
    );
    fireEvent.change(
      screen.getByLabelText("Documented authorization evidence reference"),
      { target: { value: "SOW Contract #2026-99" } }
    );

    const submitBtn = screen.getByRole("button", { name: "Register authorized target" });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        "/api/targets",
        expect.objectContaining({
          name: "New Client Portal",
          owner_organization: "Client Corp",
          scope_domains: ["client.com"],
          evidence_reference: "SOW Contract #2026-99",
        })
      );
    });
  });

  it("rejects URLs in scope domains field during target registration", async () => {
    mockAppGet();
    render(<App />);
    const registerBtn = await screen.findByRole("button", { name: /Register target/i });
    fireEvent.click(registerBtn);

    fireEvent.change(screen.getByLabelText("Target friendly name"), {
      target: { value: "OWASP Juice Shop" },
    });
    fireEvent.change(screen.getByLabelText("Target owner or organization"), {
      target: { value: "OWASP Foundation" },
    });
    fireEvent.change(
      screen.getByLabelText(/In-scope domains and IP addresses/),
      { target: { value: "http://127.0.0.1:3000" } }
    );
    fireEvent.change(
      screen.getByLabelText("Documented authorization evidence reference"),
      { target: { value: "Local Lab Approval" } }
    );

    const submitBtn = screen.getByRole("button", { name: "Register authorized target" });
    fireEvent.click(submitBtn);

    expect(await screen.findByRole("alert")).toHaveTextContent("Scope entry 'http://127.0.0.1:3000' is a URL or endpoint");
    expect(api.post).not.toHaveBeenCalled();
  });

  it("registers target with canonical CIDR network", async () => {
    mockAppGet();
    api.post.mockResolvedValueOnce({
      data: { data: { id: "target-juice", name: "OWASP Juice Shop" } },
    });

    render(<App />);
    const registerBtn = await screen.findByRole("button", { name: /Register target/i });
    fireEvent.click(registerBtn);

    fireEvent.change(screen.getByLabelText("Target friendly name"), {
      target: { value: "OWASP Juice Shop" },
    });
    fireEvent.change(screen.getByLabelText("Target owner or organization"), {
      target: { value: "OWASP Foundation" },
    });
    fireEvent.change(
      screen.getByLabelText(/In-scope domains and IP addresses/),
      { target: { value: "127.0.0.1/32" } }
    );
    fireEvent.change(
      screen.getByLabelText("Documented authorization evidence reference"),
      { target: { value: "Local Lab Approval" } }
    );

    const submitBtn = screen.getByRole("button", { name: "Register authorized target" });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        "/api/targets",
        expect.objectContaining({
          name: "OWASP Juice Shop",
          scope_domains: ["127.0.0.1/32"],
        })
      );
    });
  });

  it("opens target details modal and renders scope and audit history", async () => {
    mockAppGet();
    render(<App />);

    const detailsBtn = await screen.findByRole("button", { name: "Details" });
    fireEvent.click(detailsBtn);

    expect(await screen.findByRole("dialog", { name: "Target Details" })).toBeInTheDocument();
    expect(screen.getByText("Board Authorization 2026")).toBeInTheDocument();
    expect(screen.getByText("Audit history (1 events):")).toBeInTheDocument();
  });

  it("opens deactivate modal and submits deactivation", async () => {
    mockAppGet();
    api.post.mockResolvedValueOnce({
      data: { data: { id: "target-1234", status: "inactive" } },
    });

    render(<App />);
    const deactivateBtn = await screen.findByRole("button", { name: "Deactivate" });
    fireEvent.click(deactivateBtn);

    expect(screen.getByRole("dialog", { name: "Deactivate target" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Reason for deactivation/), {
      target: { value: "Assessment project completed." },
    });

    const confirmBtn = screen.getByRole("button", { name: /Deactivate target/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        "/api/targets/target-1234/deactivate",
        expect.objectContaining({
          status: "inactive",
          reason: "Assessment project completed.",
        })
      );
    });
  });

  it("previews imported bounty scope and requires explicit approval", async () => {
    const bounty = { ...mockTargets[0], target_type: "bug_bounty" };
    mockAppGet([bounty]);
    const preview = {
      id: "snapshot-1",
      provider: "SyntheticOfflineProgram",
      program_id: "program-1",
      source_url: "https://programs.example.test/program-1",
      snapshot_version: "fixture-v1",
      digest: "sha256:synthetic",
      imported_at: "2026-01-01T00:00:00Z",
      last_successful_validation_at: new Date().toISOString(),
      import_status: "valid",
      approval_status: "pending_review",
      included_assets: [{ asset_type: "domain", value: "bounty.example.test" }],
      excluded_assets: [{ asset_type: "path", value: "/admin" }],
      permitted_methods: ["web_service_discovery"],
      prohibited_methods: ["dos"],
      restrictions: ["Synthetic only"],
      invalid_entries: [],
      scope_diff: {
        newly_included: [{ asset_type: "domain", value: "bounty.example.test" }],
        removed: [],
        exclusions_added: [],
        exclusions_removed: [],
        methods_changed: true,
      },
    };
    api.post
      .mockResolvedValueOnce({ data: { data: preview } })
      .mockResolvedValueOnce({ data: { data: { snapshot: { ...preview, approval_status: "approved" } } } });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));
    fireEvent.click(await screen.findByRole("button", { name: "Import offline JSON" }));
    fireEvent.change(screen.getByLabelText("Provider name"), { target: { value: "SyntheticOfflineProgram" } });
    fireEvent.change(screen.getByLabelText("Program identifier"), { target: { value: "program-1" } });
    fireEvent.change(screen.getByLabelText("Source URL (reference only)"), {
      target: { value: "https://programs.example.test/program-1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Preview scope changes" }));

    expect(await screen.findByText("Scope diff requiring review")).toBeInTheDocument();
    expect(api.post).toHaveBeenNthCalledWith(
      1,
      "/api/targets/target-1234/scope-imports/preview",
      expect.objectContaining({
        provider: "SyntheticOfflineProgram",
        program_id: "program-1",
        fixture: expect.objectContaining({ version: "offline-fixture-v1" }),
      }),
    );
    expect(screen.getByRole("button", { name: "Approve imported scope" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve imported scope" }));
    await waitFor(() => {
      expect(api.post).toHaveBeenNthCalledWith(
        2,
        "/api/targets/target-1234/scope-imports/snapshot-1/approve",
        {},
      );
    });
  });

  it("renders scope-import panel exactly once when multiple audit events exist", async () => {
    const multiAuditBounty = {
      ...mockTargets[0],
      target_type: "bug_bounty",
      audit_events: [
        {
          id: 1,
          target_id: "target-1234",
          event_type: "created",
          actor: "security_admin",
          details: { name: "Corporate Web App" },
          created_at: "2026-01-01T00:00:00Z",
        },
        {
          id: 2,
          target_id: "target-1234",
          event_type: "updated",
          actor: "security_lead",
          details: { rate_limit_rps: 15 },
          created_at: "2026-01-02T12:00:00Z",
        },
        {
          id: 3,
          target_id: "target-1234",
          event_type: "scope_import_approved",
          actor: "security_lead",
          details: { digest: "sha256:test" },
          created_at: "2026-01-03T15:00:00Z",
        },
      ],
    };
    mockAppGet([multiAuditBounty]);

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    // Assert audit history renders all events
    expect(await screen.findByText(/Audit history \(3 events\)/i)).toBeInTheDocument();

    // Assert that the scope-import panel appears EXACTLY ONCE
    const panelTitles = screen.getAllByText("Offline bug bounty scope imports");
    expect(panelTitles).toHaveLength(1);
    const importButtons = screen.getAllByRole("button", { name: "Import offline JSON" });
    expect(importButtons).toHaveLength(1);
  });

  it("renders scope-import history containing multiple records correctly", async () => {
    const bounty = { ...mockTargets[0], target_type: "bug_bounty" };
    const historyRecords = [
      {
        id: "snapshot-hist-1",
        provider: "BugcrowdSynthetic",
        program_id: "program-alpha",
        source_url: "https://bugcrowd.test/alpha",
        snapshot_version: "v1",
        digest: "sha256:hist1",
        imported_at: "2026-01-10T10:00:00Z",
        last_successful_validation_at: "2026-01-10T10:00:00Z",
        import_status: "valid",
        approval_status: "approved",
        included_assets: [{ asset_type: "domain", value: "alpha.test" }],
        excluded_assets: [],
        permitted_methods: ["web_service_discovery"],
        prohibited_methods: ["dos"],
        restrictions: [],
        invalid_entries: [],
        scope_diff: {
          newly_included: [{ asset_type: "domain", value: "alpha.test" }],
          removed: [],
          exclusions_added: [],
          exclusions_removed: [],
          methods_changed: false,
        },
      },
      {
        id: "snapshot-hist-2",
        provider: "HackerOneSynthetic",
        program_id: "program-beta",
        source_url: "https://hackerone.test/beta",
        snapshot_version: "v2",
        digest: "sha256:hist2",
        imported_at: "2026-01-12T14:00:00Z",
        last_successful_validation_at: "2026-01-12T14:00:00Z",
        import_status: "valid",
        approval_status: "rejected",
        included_assets: [{ asset_type: "domain", value: "beta.test" }],
        excluded_assets: [],
        permitted_methods: ["port_scan"],
        prohibited_methods: ["dos"],
        restrictions: [],
        invalid_entries: [],
        scope_diff: {
          newly_included: [{ asset_type: "domain", value: "beta.test" }],
          removed: [],
          exclusions_added: [],
          exclusions_removed: [],
          methods_changed: true,
        },
      },
    ];
    mockAppGet([bounty], { data: { data: historyRecords } });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    // Assert that import history header displays the count of 2 records
    expect(await screen.findByText("Import history (2)")).toBeInTheDocument();
    // Assert both history records render with their provider and target details
    expect(screen.getByText(/BugcrowdSynthetic/i)).toBeInTheDocument();
    expect(screen.getByText(/HackerOneSynthetic/i)).toBeInTheDocument();
    expect(screen.getAllByText(/alpha\.test/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/beta\.test/i).length).toBeGreaterThanOrEqual(1);
  });

  it("handles empty scope-import history and API errors safely", async () => {
    const bounty = { ...mockTargets[0], target_type: "bug_bounty" };

    // Part A: Empty import-history response
    mockAppGet([bounty], { data: { data: [] } });
    const { unmount } = render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Import history (0)")).toBeInTheDocument();
    expect(screen.getByText("No scope import history recorded.")).toBeInTheDocument();
    unmount();

    // Part B: API error when fetching import history
    mockAppGet([bounty], new Error("Network error fetching import history"));
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Details" }));

    expect(await screen.findByText("Network error fetching import history")).toBeInTheDocument();
  });

  describe("Phase 3 Automated Assessment Workflow", () => {
    beforeEach(() => {
      window.location.hash = "#/new";
    });

    it("renders authorized target selector, binds target_id, and displays configuration preview", async () => {
      mockAppGet();
      api.post.mockResolvedValueOnce({
        data: { data: { id: "scan-9999", target: "example.com" } },
      });

      render(<App />);

      expect(await screen.findByRole("heading", { name: "Start an assessment" })).toBeInTheDocument();

      // Check for target selector dropdown
      const selectTarget = await screen.findByLabelText(/Authorized Target Profile/i);
      expect(selectTarget).toBeInTheDocument();

      // Select registered target
      fireEvent.change(selectTarget, { target: { value: "target-1234" } });

      // Target summary card and preview should render
      expect((await screen.findAllByText("Corporate Web App"))[0]).toBeInTheDocument();
      expect(screen.getAllByText(/ACME Corp/)[0]).toBeInTheDocument();
      expect(screen.getByText(/10 req\/sec/)).toBeInTheDocument();
      expect(screen.getByText(/Excluded scope \(protected\)/)).toBeInTheDocument();
      expect(screen.getByText(/\/admin\/billing/)).toBeInTheDocument();

      // Configuration preview should be displayed
      expect(screen.getByText("Assessment Configuration Preview")).toBeInTheDocument();
      expect(screen.getByText("Verified")).toBeInTheDocument();

      // Authorize and submit
      fireEvent.click(screen.getByLabelText(/I own this target/i));
      const submitBtn = screen.getByRole("button", { name: "Start assessment" });
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith(
          "/api/scans",
          expect.objectContaining({
            target: "example.com",
            target_id: "target-1234",
            profile: "quick",
            authorized: true,
          }),
          expect.any(Object)
        );
      });
    });

    it("correctly populates authorized target dropdown from the API response envelope and handles empty states", async () => {
      // 1. Empty state
      mockAppGet([]);
      const { unmount } = render(<App />);
      expect(await screen.findByRole("heading", { name: "Start an assessment" })).toBeInTheDocument();
      expect(await screen.findByText(/no registered authorized targets/i)).toBeInTheDocument();
      unmount();

      // 2. Envelope data extraction with populated targets
      mockAppGet(mockTargets);
      render(<App />);
      const select = await screen.findByLabelText(/Authorized Target Profile/i);
      expect(select).toBeInTheDocument();
      expect(screen.getByRole("option", { name: /Corporate Web App \(ACME Corp\)/i })).toBeInTheDocument();
    });
  });
});
