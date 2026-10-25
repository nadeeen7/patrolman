import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  timeout: 30000,
  withCredentials: true,
});

let csrfToken = "";

export function setCsrfToken(token) {
  csrfToken = token || "";
}

// Login and signup run before a server session exists, so they use a
// pre-session token delivered in the SameSite=Strict patrolman_csrf cookie.
export async function refreshCsrfToken() {
  const response = await api.get("/api/auth/csrf");
  const token = response.data?.data?.csrf_token || "";
  setCsrfToken(token);
  return token;
}

api.interceptors.request.use((config) => {
  if (csrfToken && !["get", "head", "options"].includes(config.method?.toLowerCase())) {
    config.headers["X-CSRF-Token"] = csrfToken;
  }
  return config;
});

export function isCancel(error) {
  return (
    axios.isCancel(error) ||
    error?.code === "ERR_CANCELED" ||
    error?.name === "CanceledError" ||
    error?.name === "AbortError"
  );
}

export function errorMessage(error) {
  if (error.response?.data?.error?.message) {
    return error.response.data.error.message;
  }
  if (error.response?.status === 500) {
    return "Server error (500). Please verify target configuration and try again.";
  }
  return (
    error.message ||
    "Request failed. Please try again."
  );
}

export async function download(id, format, filename) {
  const response = await api.get(`/api/scans/${id}/report`, {
    params: { format },
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const a = document.createElement("a");
  a.href = url;
  a.download =
    format === "pdf"
      ? (filename || `assessment_report_${id.slice(0, 8)}.pdf`)
      : format === "html"
        ? "report.html"
        : format === "json"
          ? "scan.json"
          : "vulnerabilities.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function downloadEvidence(id, filename, format = "raw") {
  const response = await api.get(`/api/evidence/${id}/download`, {
    params: format === "pdf" ? { format: "pdf" } : undefined,
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || (format === "pdf" ? "evidence_report.pdf" : "evidence.txt");
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function downloadEvidencePdf(id, filename) {
  return downloadEvidence(id, filename, "pdf");
}

export async function previewEvidencePdf(id) {
  const response = await api.get(`/api/evidence/${id}/preview`, {
    responseType: "blob",
  });
  const fileBlob = new Blob([response.data], { type: "application/pdf" });
  const fileUrl = URL.createObjectURL(fileBlob);
  window.open(fileUrl, "_blank");
  setTimeout(() => URL.revokeObjectURL(fileUrl), 60000);
  return fileUrl;
}

export async function changePassword({ current_password, new_password, confirm_password }) {
  const response = await api.post("/api/auth/change-password", {
    current_password,
    new_password,
    confirm_password,
  });
  return response.data;
}

