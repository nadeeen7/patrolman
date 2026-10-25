import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { beforeEach, describe, it, expect, vi } from "vitest";
import App from "./App";
import { api, downloadEvidence, downloadEvidencePdf } from "./api";

vi.mock("./api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  setCsrfToken: vi.fn(),
  refreshCsrfToken: vi.fn().mockResolvedValue("synthetic-csrf-token"),
  errorMessage: (e) => e.message,
  download: vi.fn(),
  downloadEvidence: vi.fn().mockResolvedValue(undefined),
  downloadEvidencePdf: vi.fn().mockResolvedValue(undefined),
}));

const mockAuditEvents = [
  {
    id: "audit-123",
    event_type: "scan_dispatched",
    actor: "security_admin",
    resource_type: "scan",
    resource_id: "scan-999",
    details: { target: "127.0.0.1", profile: "quick" },
    ip_address: "127.0.0.1",
    created_at: "2026-10-18T01:00:00Z",
  },
  {
    id: "audit-124",
    event_type: "target_created",
    actor: "security_admin",
    resource_type: "target",
    resource_id: "target-1234",
    details: { name: "Local Test Server" },
    ip_address: "127.0.0.1",
    created_at: "2026-10-18T00:30:00Z",
  },
];

const mockEvidence = [
  {
    id: "ev-555",
    scan_id: "scan-999",
    finding_id: null,
    execution_id: 1,
    tool: "nmap",
    evidence_type: "raw_output",
    file_path: "scans/scan-999/ev-555_nmap_raw_output.txt",
    file_size: 2048,
    sha256_hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    redacted: false,
    created_at: "2026-10-18T01:05:00Z",
  },
];

function setupApiMocks(auditEvents = mockAuditEvents, evidenceItems = mockEvidence) {
  api.get.mockImplementation((path) => {
    if (path === "/api/auth/status") {
      return Promise.resolve({ data: { data: { administrator_initialized: true } } });
    }
    if (path === "/api/auth/session") {
      return Promise.resolve({ data: { data: { username: "security_admin", csrf_token: "csrf-token" } } });
    }
    if (path === "/api/dashboard") {
      return Promise.resolve({
        data: {
          data: {
            total_scans: 1,
            states: { completed: 1 },
            total_findings: 0,
            severities: {},
            coverage: {},
            recent: [],
          },
        },
      });
    }
    if (path.startsWith("/api/audit-events")) {
      return Promise.resolve({
        data: {
          data: auditEvents,
          meta: { page: 1, page_size: 20, total: auditEvents.length },
        },
      });
    }
    if (path.startsWith("/api/evidence")) {
      return Promise.resolve({
        data: {
          data: evidenceItems,
          meta: { page: 1, page_size: 20, total: evidenceItems.length },
        },
      });
    }
    return Promise.resolve({ data: { data: [], meta: { total: 0 } } });
  });
}

describe("Phase 4: Audit Trail & Evidence Locker Views", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the Audit Trail view and displays audit events", async () => {
    setupApiMocks();
    window.location.hash = "#/audit";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Audit trail" })).toBeInTheDocument();
    expect(screen.getByText("COMPLIANCE & TRACEABILITY")).toBeInTheDocument();
    expect((await screen.findAllByText("scan dispatched")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("target created").length).toBeGreaterThan(0);
    expect(screen.getAllByText("security_admin").length).toBeGreaterThan(0);
  });

  it("opens audit event detail modal when Inspect details is clicked", async () => {
    setupApiMocks();
    window.location.hash = "#/audit";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Audit trail" })).toBeInTheDocument();

    const inspectButtons = await screen.findAllByText("Inspect details");
    fireEvent.click(inspectButtons[0]);

    expect(await screen.findByText("AUDIT RECORD")).toBeInTheDocument();
    expect(screen.getByText("Redacted payload details")).toBeInTheDocument();
    expect(screen.getAllByText(/127\.0\.0\.1/).length).toBeGreaterThan(0);

    // Close modal
    const closeBtn = screen.getByLabelText("Close details");
    fireEvent.click(closeBtn);
    await waitFor(() => {
      expect(screen.queryByText("AUDIT RECORD")).not.toBeInTheDocument();
    });
  });

  it("filters audit events by event type", async () => {
    setupApiMocks();
    window.location.hash = "#/audit";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Audit trail" })).toBeInTheDocument();

    const select = screen.getByLabelText("Filter event type");
    fireEvent.change(select, { target: { value: "scan_dispatched" } });

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith(
        expect.stringContaining("event_type=scan_dispatched"),
        expect.anything()
      );
    });
  });

  it("renders empty state when no audit events exist", async () => {
    setupApiMocks([], []);
    window.location.hash = "#/audit";
    render(<App />);

    expect(await screen.findByText("No audit events found")).toBeInTheDocument();
  });

  it("renders the Evidence Locker view and displays evidence artifacts", async () => {
    setupApiMocks();
    window.location.hash = "#/evidence";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Evidence locker" })).toBeInTheDocument();
    expect(screen.getByText("VERIFIABLE ARTIFACTS")).toBeInTheDocument();
    expect((await screen.findAllByText("nmap")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("raw output").length).toBeGreaterThan(0);
    expect(screen.getByText("2 KB")).toBeInTheDocument();
    expect(screen.getByText("abcdef123456…")).toBeInTheDocument();
  });

  it("triggers evidence download when Download button is clicked", async () => {
    setupApiMocks();
    window.location.hash = "#/evidence";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Evidence locker" })).toBeInTheDocument();

    const downloadBtn = await screen.findByRole("button", { name: /Download/i });
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(downloadEvidence).toHaveBeenCalledWith(
        "ev-555",
        "nmap_raw_output_ev-555.txt"
      );
    });
  });

  it("triggers derived evidence PDF export when PDF button is clicked", async () => {
    setupApiMocks();
    window.location.hash = "#/evidence";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Evidence locker" })).toBeInTheDocument();

    const pdfBtn = await screen.findByRole("button", { name: /Export PDF report/i });
    fireEvent.click(pdfBtn);

    await waitFor(() => {
      expect(downloadEvidencePdf).toHaveBeenCalledWith(
        "ev-555",
        "nmap_raw_output_ev-555_report.pdf"
      );
    });
  });

  it("opens verified evidence modal with SHA-256 hash when digest code is clicked", async () => {
    setupApiMocks();
    window.location.hash = "#/evidence";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Evidence locker" })).toBeInTheDocument();

    const digestElem = await screen.findByText("abcdef123456…");
    fireEvent.click(digestElem);

    expect(await screen.findByText("VERIFIED EVIDENCE ARTIFACT")).toBeInTheDocument();
    expect(
      screen.getByText("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download Raw Artifact" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download Derived PDF" })).toBeInTheDocument();
  });

  it("renders empty state when no evidence records exist", async () => {
    setupApiMocks([], []);
    window.location.hash = "#/evidence";
    render(<App />);

    expect(await screen.findByText("No evidence artifacts")).toBeInTheDocument();
  });
});
