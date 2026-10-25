import React, { useState, useEffect, useRef } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  Radar,
  History,
  Layers,
  ArrowUpRight,
  ArrowRight,
  Plus,
  ChevronRight,
  Check,
  AlertTriangle,
  Download,
  X,
  LogOut,
  RefreshCw,
  Globe,
  Terminal,
  Activity,
  ChevronLeft,
  Square,
  Sun,
  Moon,
  Eye,
  EyeOff,
  Target,
  ChartNoAxesColumnIncreasing,
  UserRound,
  KeyRound,
  Calendar,
  Clock,
  FileText,
  Ban,
  Edit2,
  CheckCircle2,
  Menu,
  Search,
  Settings,
  BookOpen,
  XCircle,
  Info,
  Copy,
} from "lucide-react";
import { api, setCsrfToken, refreshCsrfToken, errorMessage, download, downloadEvidence, downloadEvidencePdf, previewEvidencePdf, changePassword } from "./api";
import { useTheme } from "./theme";
const terminal = ["completed", "completed_with_errors", "failed", "cancelled"],
  severities = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
  ];
const TARGET_METHOD_OPTIONS = [
  ["port_scan", "Port scan (Nmap)"],
  ["web_service_discovery", "Web service discovery (httpx, whatweb, subfinder)"],
  ["tls_audit", "TLS / SSL audit (SSLyze)"],
  ["vulnerability_check", "Vulnerability verification (Nuclei, Wapiti)"],
  ["active_crawl", "Active web crawl (Wapiti)"],
  ["local_scan", "Local filesystem scan (Gitleaks, Trivy)"],
];

const TARGET_PROHIBITED_OPTIONS = [
  ["dos", "Denial of service"],
  ["exploit", "Exploit execution"],
  ["credential_attack", "Credential attacks"],
  ["active_crawl", "Active crawl"],
  ["local_scan", "Local filesystem scan"],
  ["port_scan", "Port scan"],
];

const go = (path) => (window.location.hash = path),
  pretty = (v) => String(v || "").replaceAll("_", " "),
  date = (v) => (v ? new Date(v).toLocaleString() : "—");
function getBadgeIcon(stateClass) {
  if (stateClass === "completed_without_findings") {
    return <Check size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (stateClass === "completed_with_findings" || stateClass === "completed_with_errors") {
    return <AlertTriangle size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["skipped", "disabled_for_safety", "disabled"].includes(stateClass)) {
    return <Ban size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["failed", "critical", "high", "blocked", "blocked_by_policy", "execution_blocked", "not_permitted"].includes(stateClass)) {
    return <XCircle size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["running", "in_progress"].includes(stateClass)) {
    return <Activity size={11} className="badge-icon spin" aria-hidden="true" />;
  }
  if (["timed_out", "queued", "pending"].includes(stateClass)) {
    return <Clock size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["configuration_required", "unverified", "version_unverified", "needs_nmap", "needs_httpx"].includes(stateClass)) {
    return <AlertTriangle size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["ready", "completed", "active"].includes(stateClass)) {
    return <Check size={11} className="badge-icon" aria-hidden="true" />;
  }
  if (["informational", "web", "technology"].includes(stateClass)) {
    return <Info size={11} className="badge-icon" aria-hidden="true" />;
  }
  return null;
}

function Badge({ value, label, showIcon = true }) {
  const raw = String(value || "").toLowerCase().trim();
  const stateClass = raw.replace(/[\s-]+/g, "_");
  const colorClass =
    stateClass === "completed_without_findings"
      ? "completed_without_findings"
      : stateClass === "completed_with_findings"
        ? "completed_with_findings"
        : stateClass.startsWith("completed_with") && stateClass !== "completed_with_errors"
          ? "completed"
          : ["blocked_by_policy", "blocked", "prohibited", "not_permitted", "revoked", "failed", "critical", "high"].includes(stateClass)
            ? "blocked"
            : ["needs_nmap", "needs_httpx", "prereq"].includes(stateClass)
              ? "needs_nmap"
              : ["version_check_pending"].includes(stateClass)
                ? "version_check_pending"
                : ["unverified", "version_unverified", "configuration_required"].includes(stateClass)
                  ? "unverified"
                  : stateClass;
  const icon = showIcon ? getBadgeIcon(stateClass) : null;
  return (
    <span className={`badge ${stateClass} ${colorClass}`}>
      {icon}
      <span>{label || pretty(value)}</span>
    </span>
  );
}
function ErrorBox({ message, id }) {
  return message ? (
    <div className="error" id={id} role="alert">
      <AlertTriangle size={17} />
      {message}
    </div>
  ) : null;
}
function Empty({ title = "Nothing here yet", children }) {
  return (
    <div className="empty">
      <Radar size={34} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function Heading({ title, eyebrow, children, action }) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{children}</p>
      </div>
      {action}
    </div>
  );
}

function isCanceled(e) {
  return Boolean(
    e?.code === "ERR_CANCELED" ||
    e?.name === "CanceledError" ||
    e?.name === "AbortError"
  );
}

export const appDataCache = new Map();
export function clearAppDataCache() {
  appDataCache.clear();
}

function useLoad(path, interval = 0) {
  const [data, setData] = useState(() => (appDataCache.has(path) ? appDataCache.get(path) : null)),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(() => !appDataCache.has(path)),
    [revision, bump] = useState(0);
  useEffect(() => {
    let alive = true;
    let timerId = null;
    let inFlight = false;
    let failureCount = 0;
    let hasSuccess = false;
    const controller = new AbortController();
    if (!appDataCache.has(path)) {
      setLoading(true);
    }
    async function load() {
      if (inFlight || !alive) return;
      inFlight = true;
      try {
        const r = await api.get(path, { signal: controller.signal });
        if (alive) {
          appDataCache.set(path, r.data);
          setData(r.data);
          hasSuccess = true;
          failureCount = 0;
          setError("");
        }
      } catch (e) {
        if (!alive || isCanceled(e)) return;
        failureCount++;
        // If actively polling in the background after a successful load,
        // tolerate a single transient failure before flashing an error banner.
        // For initial loads or persistent consecutive failures, surface the error immediately.
        if (!hasSuccess || failureCount >= 2) {
          setError(errorMessage(e));
        }
      } finally {
        inFlight = false;
        if (alive) {
          setLoading(false);
          if (interval > 0) {
            timerId = setTimeout(load, interval);
          }
        }
      }
    }
    load();
    return () => {
      alive = false;
      controller.abort();
      if (timerId) clearTimeout(timerId);
    };
  }, [path, interval, revision]);
  return {
    data: data?.data,
    meta: data?.meta,
    error,
    loading,
    reload: () => bump((x) => x + 1),
  };
}
export default function App() {
  const [authenticated, setAuthenticated] = useState(false),
    [authChecked, setAuthChecked] = useState(false),
    [path, setPath] = useState(window.location.hash.slice(1) || "/"),
    [authView, setAuthView] = useState("login"),
    [adminInitialized, setAdminInitialized] = useState(null),
    [registrationEnabled, setRegistrationEnabled] = useState(true),
    [username, setUsername] = useState(""),
    [currentUser, setCurrentUser] = useState(""),
    [password, setPassword] = useState(""),
    [confirmPassword, setConfirmPassword] = useState(""),
    [error, setError] = useState(""),
    [loginBusy, setLoginBusy] = useState(false),
    [showPassword, setShowPassword] = useState(false),
    [showConfirmPassword, setShowConfirmPassword] = useState(false),
    [logoutError, setLogoutError] = useState(""),
    [backendError, setBackendError] = useState(""),
    [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();
  useEffect(() => {
    const change = () => {
      setPath(window.location.hash.slice(1) || "/");
      setMobileNavOpen(false);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    let alive = true;
    sessionStorage.removeItem("ava-token");
    api.get("/api/auth/status")
      .then(async (statusResponse) => {
        if (!alive) return;
        const initialized = statusResponse.data.data.administrator_initialized;
        const registrationOpen = statusResponse.data.data.registration_enabled !== false;
        setAdminInitialized(initialized);
        setRegistrationEnabled(registrationOpen);
        if (!initialized) {
          setAuthView(registrationOpen ? "signup" : "login");
          if (!registrationOpen) {
            setBackendError(
              "Registration is disabled for this installation. Initialize the administrator from the command line.",
            );
          }
          return;
        }
        try {
          const response = await api.get("/api/auth/session");
          if (!alive) return;
          setCsrfToken(response.data.data.csrf_token);
          if (response.data.data.username) setCurrentUser(response.data.data.username);
          setAuthenticated(true);
        } catch {
          if (alive) {
            setCsrfToken("");
            setAuthenticated(false);
            setAuthView("login");
          }
        }
      })
      .catch((e) => {
        if (alive) {
          setCsrfToken("");
          setAuthenticated(false);
          setBackendError(
            e.response?.status === 404
              ? "The running backend must be restarted to enable administrator login."
              : "",
          );
        }
      })
      .finally(() => {
        if (alive) setAuthChecked(true);
      });
    return () => {
      alive = false;
    };
  }, []);
  async function authenticate(e) {
    e.preventDefault();
    setLoginBusy(true);
    setError("");
    if (authView === "signup" && password !== confirmPassword) {
      setError("Passwords do not match.");
      setLoginBusy(false);
      return;
    }
    if (authView === "signup" && password.length < 8) {
      setError("Password must contain at least 8 characters.");
      setLoginBusy(false);
      return;
    }
    try {
      // Obtain the pre-session CSRF token before submitting credentials.
      await refreshCsrfToken();
      const response = await api.post(
        authView === "signup" ? "/api/auth/signup" : "/api/auth/login",
        authView === "signup"
          ? { username, password, confirm_password: confirmPassword }
          : { username, password },
      );
      setCsrfToken(response.data.data.csrf_token);
      setCurrentUser(response.data.data.username || username || "admin");
      setAdminInitialized(true);
      setAuthenticated(true);
      setPassword("");
      setConfirmPassword("");
    } catch (e) {
      if (e.response?.status === 409) {
        setError(errorMessage(e) || "Registration could not be completed. Choose a different username and try again.");
      } else if (e.response?.status === 401) {
        setError("The username or password was not recognized.");
      } else if (e.response?.status === 429) {
        setError("Sign-in is temporarily unavailable. Try again later.");
      } else if (e.response?.status === 503) {
        setError("Administrator setup is required before sign-in.");
      } else if (!e.response) {
        setError("Cannot connect to the local backend. Confirm the server is running and try again.");
      } else {
        setError(errorMessage(e));
      }
    } finally {
      setLoginBusy(false);
    }
  }
  if (!authChecked)
    return <div className="login-loading" role="status">Checking your secure session…</div>;
  if (!authenticated)
    return (
      <div className="login">
        <div className="login-art">
          <div className="brand">
            <ShieldCheck /> PATROLMAN<span>Automated Vulnerability Assessment Framework</span>
          </div>
          <div>
            <span className="eyebrow">KNOW YOUR ATTACK SURFACE</span>
            <h1>
              Clarity before
              <br />
              <span>complexity.</span>
            </h1>
            <p>
              A focused workspace for authorized security assessments, evidence,
              and remediation.
            </p>
            <div className="login-features">
              <div className="login-feature">
                <span className="feature-icon"><Target size={22} /></span>
                <span><strong>Identify risk</strong><small>Discover vulnerabilities across your environment.</small></span>
              </div>
              <div className="login-feature">
                <span className="feature-icon"><ChartNoAxesColumnIncreasing size={22} /></span>
                <span><strong>Prioritize findings</strong><small>Focus on what matters with clear evidence.</small></span>
              </div>
              <div className="login-feature">
                <span className="feature-icon"><ShieldCheck size={22} /></span>
                <span><strong>Track remediation</strong><small>Move from assessment to action with confidence.</small></span>
              </div>
            </div>
          </div>
          <small>Controlled scope. Authorized access. Transparent results.</small>
        </div>
        <div className="login-form">
          <span className="eyebrow">LOCAL WORKSPACE</span>
          <h2>Welcome to PATROLMAN</h2>
          <p>Sign in to securely access your assessment workspace.</p>
          <ErrorBox message={backendError} />
          <div className="auth-tabs" role="tablist" aria-label="Administrator authentication">
            <button
              type="button"
              role="tab"
              id="login-tab"
              aria-selected={authView === "login"}
              aria-controls="auth-panel"
              className={authView === "login" ? "active" : ""}
              onClick={() => {
                setAuthView("login");
                setError("");
              }}
            >
              Admin Login
            </button>
            <button
              type="button"
              role="tab"
              id="signup-tab"
              aria-selected={authView === "signup"}
              aria-controls="auth-panel"
              aria-disabled={!registrationEnabled}
              className={authView === "signup" ? "active" : ""}
              onClick={() => {
                if (!registrationEnabled) return;
                setAuthView("signup");
                setError("");
              }}
            >
              Admin Sign Up
            </button>
          </div>
          <form
            id="auth-panel"
            role="tabpanel"
            aria-labelledby={authView === "signup" ? "signup-tab" : "login-tab"}
            onSubmit={authenticate}
          >
            <label htmlFor="username">Username</label>
            <div className="input-icon">
              <UserRound size={17} aria-hidden="true" />
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  setError("");
                }}
                placeholder="Enter your username"
                required
                autoComplete="username"
                maxLength={64}
                aria-describedby={error ? "login-error" : undefined}
              />
            </div>
            <label htmlFor="password">Password</label>
            <div className="input-icon">
              <KeyRound size={17} aria-hidden="true" />
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setError("");
                }}
                placeholder={authView === "signup" ? "Create a secure password" : "Enter your password"}
                required
                autoComplete={authView === "signup" ? "new-password" : "current-password"}
                maxLength={1024}
                minLength={authView === "signup" ? 8 : undefined}
                aria-describedby={error ? "login-error" : undefined}
              />
              <button
                className="token-visibility"
                type="button"
                aria-label={showPassword ? "Hide password" : "Show password"}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((visible) => !visible)}
              >
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>
            {authView === "signup" && (
              <>
                <label htmlFor="confirm-password">Confirm Password</label>
                <div className="input-icon">
                  <KeyRound size={17} aria-hidden="true" />
                  <input
                    id="confirm-password"
                    type={showConfirmPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      setError("");
                    }}
                    placeholder="Re-enter your password"
                    required
                    autoComplete="new-password"
                    maxLength={1024}
                    minLength={8}
                    aria-describedby={error ? "login-error" : undefined}
                  />
                  <button
                    className="token-visibility"
                    type="button"
                    aria-label={showConfirmPassword ? "Hide confirmation password" : "Show confirmation password"}
                    aria-pressed={showConfirmPassword}
                    onClick={() => setShowConfirmPassword((visible) => !visible)}
                  >
                    {showConfirmPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                  </button>
                </div>
              </>
            )}
            <ErrorBox id="login-error" message={error} />
            <button className="primary" type="submit" disabled={loginBusy || adminInitialized === null}>
              {loginBusy
                ? authView === "signup" ? "Creating account…" : "Signing in…"
                : authView === "signup" ? "Create Admin Account" : "Sign In"}
              {!loginBusy && <ArrowRight size={17} />}
            </button>
          </form>
          <small>
            {authView === "signup"
              ? !registrationEnabled
                ? "Registration is disabled for this installation."
                : adminInitialized === true
                  ? "Create another administrator account for this local PATROLMAN installation."
                  : "Create the first administrator for this local PATROLMAN installation."
              : "Your administrator session is protected and stays on this local server."}
          </small>
        </div>
      </div>
    );
  const handleLogout = async () => {
    setLogoutError("");
    try {
      await api.post("/api/auth/logout");
      setCsrfToken("");
      setCurrentUser("");
      setAuthenticated(false);
      setPassword("");
      setPath("/");
      window.location.hash = "#/";
    } catch (e) {
      setLogoutError(errorMessage(e));
    }
  };

  const section = path.startsWith("/scan/")
    ? "Scan workspace"
    : path === "/new"
      ? "New assessment"
      : path === "/targets"
        ? "Authorized targets"
        : path === "/history"
          ? "Scan history"
          : path === "/tools"
            ? "Tool integrations"
            : path === "/audit"
              ? "Audit trail"
              : path === "/evidence"
                ? "Evidence locker"
                : path === "/settings"
                  ? "Settings & preferences"
                  : path === "/help"
                    ? "Help & documentation"
                    : "Overview";
  return (
    <div className="shell">
      {mobileNavOpen && (
        <div
          className="mobile-nav-backdrop"
          onClick={() => setMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}
      <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`}>
        <a className="brand" href="#/">
          <ShieldCheck /> PATROLMAN<span>Automated Vulnerability Assessment Framework</span>
        </a>
        <div className="workspace-label">
          <span className="workspace-icon">A</span>
          <div>
            Assessment workspace<small>Local administrator</small>
          </div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {[
            ["/", "Overview", LayoutDashboard],
            ["/new", "New assessment", Radar],
            ["/targets", "Authorized targets", Target],
            ["/history", "Scan history", History],
            ["/tools", "Tool integrations", Layers],
            ["/audit", "Audit trail", FileText],
            ["/evidence", "Evidence locker", Download],
          ].map(([link, label, Icon]) => (
            <a
              key={link}
              href={"#" + link}
              className={path === link ? "active" : ""}
              onClick={() => setMobileNavOpen(false)}
            >
              <Icon size={18} />
              {label}
              {path === link && <span className="nav-dot" />}
            </a>
          ))}
        </nav>
        <div className="nav-label" style={{ marginTop: "24px" }}>SYSTEM</div>
        <nav>
          <a
            href="#/settings"
            className={`nav-subtle ${path === "/settings" ? "active" : ""}`}
            onClick={() => setMobileNavOpen(false)}
          >
            <Settings size={18} />
            Settings
          </a>
          <a
            href="#/help"
            className={`nav-subtle ${path === "/help" ? "active" : ""}`}
            onClick={() => setMobileNavOpen(false)}
          >
            <BookOpen size={18} />
            Help &amp; documentation
          </a>
        </nav>
        <div className="scope-card">
          <ShieldCheck size={22} />
          <h4>Stay within scope.</h4>
          <p>
            Only assess systems you own or have explicit permission to test.
          </p>
          <span>
            Exact-host allowlist enforced <Check size={14} />
          </span>
        </div>
        <div className="user-menu-card">
          <div className="user-badge-row">
            <div className="user-avatar" aria-hidden="true">
              A
            </div>
            <div className="user-details">
              <span className="user-name">{currentUser || "Administrator"}</span>
              <span className="user-role">Local administration</span>
            </div>
          </div>
          <button
            className="logout"
            aria-label="Disconnect workspace"
            title="Log out from PATROLMAN"
            onClick={handleLogout}
          >
            <LogOut size={16} /> Log out
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="mobile-nav-toggle"
              aria-label="Toggle navigation menu"
              onClick={() => setMobileNavOpen((prev) => !prev)}
            >
              <Menu size={18} />
            </button>
            <span className="breadcrumbs">
              Workspace <ChevronRight size={14} /> <strong>{section}</strong>
            </span>
          </div>
          <GlobalSearch onNavigate={go} />
          <span className="topbar-actions">
            <span className="local">
              <i /> Local assessment environment
            </span>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
            <ProfileMenu
              currentUser={currentUser}
              onLogout={handleLogout}
              onNavigate={go}
            />
          </span>
        </header>
        <main>
          <ErrorBox message={logoutError} />
          {path === "/new" ? (
            <NewScan />
          ) : path === "/targets" ? (
            <TargetsPage />
          ) : path === "/history" ? (
            <HistoryPage />
          ) : path === "/tools" ? (
            <Tools />
          ) : path === "/audit" ? (
            <AuditPage />
          ) : path === "/evidence" ? (
            <EvidencePage />
          ) : path === "/settings" ? (
            <SettingsPage theme={theme} onToggleTheme={toggleTheme} currentUser={currentUser} />
          ) : path === "/help" ? (
            <HelpPage />
          ) : path.startsWith("/scan/") ? (
            <ScanDetail key={path} id={path.split("/")[2]} />
          ) : (
            <Dashboard />
          )}
        </main>
        <footer>
          Patrolman Assessment Framework{" "}
          <span>Evidence first. Validate every finding.</span>
        </footer>
      </div>
    </div>
  );
}
function ThemeToggle({ theme, onToggle }) {
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={onToggle}
      aria-pressed={theme === "dark"}
      aria-label={"Switch to " + next + " theme"}
      title={"Switch to " + next + " theme"}
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
      <span className="theme-toggle-label">
        {theme === "dark" ? "Light" : "Dark"}
      </span>
    </button>
  );
}
function extractTargetHost(raw) {
  if (!raw) return "";
  let s = String(raw).trim();
  if (s.startsWith("http://") || s.startsWith("https://")) {
    try {
      const u = new URL(s);
      return u.hostname;
    } catch {
      // fallthrough
    }
  }
  const m6 = s.match(/^\[([^\]]+)\](?::\d+)?/);
  if (m6) return m6[1];
  const colonIdx = s.indexOf(":");
  if (colonIdx !== -1 && !s.includes("/")) {
    return s.slice(0, colonIdx);
  }
  if (s.endsWith("/32") || s.endsWith("/128")) {
    return s.slice(0, s.lastIndexOf("/"));
  }
  return s;
}

function normalizeEndpointPreview(raw, profile) {
  if (!raw || !raw.trim()) return "(not specified)";
  const s = raw.trim();
  if (profile === "local") return s;
  if (s.endsWith("/32") || s.endsWith("/128")) {
    return s.slice(0, s.lastIndexOf("/"));
  }
  if (s.startsWith("http://") || s.startsWith("https://")) {
    try {
      const u = new URL(s);
      const portPart = u.port ? `:${u.port}` : "";
      const pathPart = u.pathname && u.pathname !== "/" ? u.pathname.replace(/\/+$/, "") : "";
      return `${u.protocol}//${u.hostname}${portPart}${pathPart}`;
    } catch {
      return s;
    }
  }
  const colonIdx = s.indexOf(":");
  if (colonIdx !== -1 && !s.includes("/")) {
    return `http://${s}`;
  }
  return s;
}

function validateTargetInput(raw, profile) {
  if (!raw || !raw.trim()) {
    return "Enter a target hostname, IP address, or service endpoint.";
  }
  const clean = raw.trim();
  if (profile === "local") {
    return null;
  }
  if (/[\s;`$<>\\"']/.test(clean)) {
    return "Target contains whitespace or invalid characters.";
  }
  if (clean.includes("@")) {
    return "Target must not contain user credentials or '@'.";
  }
  if (clean.includes("?") || clean.includes("#")) {
    return "Query parameters and URL fragments are unsupported in target endpoints.";
  }
  if (clean.includes("://")) {
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      return "Only http:// and https:// URL schemes are supported.";
    }
  }
  return null;
}

function ScopeCheckWidget({ host, profile, targetId }) {
  const [status, setStatus] = useState(null);
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    if (!host || profile === "local") { setStatus(null); setDetail(null); return; }
    const clean = host.trim();
    if (!clean || /[\s;`$<>\\"']/.test(clean) || clean.includes("@")) { setStatus(null); return; }
    setStatus("checking");
    setDetail(null);
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const url = "/api/targets/check?host=" + encodeURIComponent(clean) + (targetId ? "&target_id=" + encodeURIComponent(targetId) : "");
        const r = await api.get(url, { signal: controller.signal });
        const d = r.data.data;
        if (!d.covered && d.reason && d.reason.includes("No authorized")) {
          setStatus("no_targets");
        } else if (d.covered) {
          setStatus("covered");
        } else {
          setStatus("uncovered");
        }
        setDetail(d);
      } catch (e) {
        if (e.code === "ERR_CANCELED") return;
        if (e.response?.status === 403) {
          setStatus("uncovered");
          setDetail({ covered: false, reason: e.response?.data?.error?.message || "Not authorized." });
        } else if (e.response?.status === 400) {
          setStatus(null);
        } else {
          setStatus("error");
        }
      }
    }, 600);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [host, profile, targetId]);
  if (!status || status === "checking") {
    return status === "checking" ? (
      <div className="scope-check scope-check--checking" aria-live="polite">
        <RefreshCw size={14} className="spin" /> Checking authorization...
      </div>
    ) : null;
  }
  if (status === "no_targets") {
    return (
      <div className="scope-check scope-check--no-targets" aria-live="polite">
        <ShieldCheck size={14} /> No authorized targets registered -- scope gate is in permissive mode.
      </div>
    );
  }
  if (status === "covered" && detail) {
    return (
      <div className="scope-check scope-check--covered" aria-live="polite">
        <CheckCircle2 size={14} />
        <span>
          Covered by{" "}
          <a href="#/targets" className="scope-target-link">{detail.matched_target?.name}</a>
          {" -- matched via "}<code>{detail.match_source}</code>
          {detail.effective_status && detail.effective_status !== "active" && (
            <> &middot; <span className="scope-warn">status: {detail.effective_status}</span></>
          )}
        </span>
      </div>
    );
  }
  if (status === "uncovered" && detail) {
    return (
      <div className="scope-check scope-check--uncovered" aria-live="polite" role="alert">
        <AlertTriangle size={14} />
        <span>
          <strong>Not in authorized scope.</strong>{" "}{detail.reason}
          {" Register this host as an "}
          <a href="#/targets" className="scope-target-link">authorized target</a>
          {" before scanning."}
        </span>
      </div>
    );
  }
  return null;
}
function ScanTable({ scans, compact = false }) {
  return (
    <div className="table-scroll">
      <table className={compact ? "compact-table" : ""}>
        <thead>
          <tr>
            <th>Target / scan</th>
            <th>Profile</th>
            <th>Status</th>
            {!compact && <th>Authorization</th>}
            <th>Findings</th>
            <th>{compact ? "Date" : "Created"}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td>
                <a className="target-link" href={"#/scan/" + s.id}>
                  <span className="target-icon">
                    <Globe size={16} />
                  </span>
                  <span>
                    {s.target}
                    <small>{s.id.slice(0, 8)}</small>
                  </span>
                </a>
              </td>
              <td className="capitalize">{s.profile}</td>
              <td>
                <Badge value={s.state} />
              </td>
              {!compact && (
                <td className="muted">
                  {s.configuration?.authorized_target_name ? (
                    <a href="#/targets" className="scope-target-link" title={"Authorization: " + s.configuration.authorized_target_name}>
                      <ShieldCheck size={13} /> {s.configuration.authorized_target_name}
                    </a>
                  ) : (
                    <span className="subtle">&mdash;</span>
                  )}
                </td>
              )}
              <td>{s.finding_count}</td>
              <td className="muted nowrap">{date(s.created_at)}</td>
              <td>
                <a aria-label={"Open scan " + s.id} href={"#/scan/" + s.id} className="open-scan-link">
                  <ArrowUpRight size={16} />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ToolCoverageDonut({ coverage = {} }) {
  const selected = coverage.selected || 0;
  const executed = coverage.executed || 0;
  const successful = coverage.successful || 0;
  const failed = coverage.failed || 0;
  const timedOut = coverage.timed_out || 0;
  const skipped = coverage.skipped || 0;

  const total = Math.max(1, (successful + failed + timedOut + skipped));
  const r = 38;
  const c = 2 * Math.PI * r;

  const pctSuccess = successful / total;
  const pctFailed = failed / total;
  const pctTimedOut = timedOut / total;
  const pctSkipped = skipped / total;

  const strokeSuccess = pctSuccess * c;
  const strokeFailed = pctFailed * c;
  const strokeTimedOut = pctTimedOut * c;
  const strokeSkipped = pctSkipped * c;

  const offsetSuccess = 0;
  const offsetFailed = -strokeSuccess;
  const offsetTimedOut = -(strokeSuccess + strokeFailed);
  const offsetSkipped = -(strokeSuccess + strokeFailed + strokeTimedOut);

  return (
    <div className="coverage-donut-card">
      <div className="donut-and-legend">
        <div className="donut-wrap">
          <svg viewBox="0 0 100 100" className="donut-svg" aria-hidden="true">
            <circle cx="50" cy="50" r={r} className="donut-bg" />
            {successful > 0 && (
              <circle
                cx="50"
                cy="50"
                r={r}
                className="donut-segment segment-success"
                strokeDasharray={`${strokeSuccess} ${c - strokeSuccess}`}
                strokeDashoffset={offsetSuccess}
              />
            )}
            {failed > 0 && (
              <circle
                cx="50"
                cy="50"
                r={r}
                className="donut-segment segment-failed"
                strokeDasharray={`${strokeFailed} ${c - strokeFailed}`}
                strokeDashoffset={offsetFailed}
              />
            )}
            {timedOut > 0 && (
              <circle
                cx="50"
                cy="50"
                r={r}
                className="donut-segment segment-timedout"
                strokeDasharray={`${strokeTimedOut} ${c - strokeTimedOut}`}
                strokeDashoffset={offsetTimedOut}
              />
            )}
            {skipped > 0 && (
              <circle
                cx="50"
                cy="50"
                r={r}
                className="donut-segment segment-skipped"
                strokeDasharray={`${strokeSkipped} ${c - strokeSkipped}`}
                strokeDashoffset={offsetSkipped}
              />
            )}
          </svg>
          <div className="donut-center-text">
            <strong>{selected}</strong>
            <small>Selected tools</small>
          </div>
        </div>
        <div className="coverage-stats-legend">
          <div className="coverage-legend-item">
            <span className="dot dot-executed" />
            <span className="legend-name">Executed</span>
            <strong className="legend-val">{Number.isInteger(executed) ? executed : "—"}</strong>
          </div>
          <div className="coverage-legend-item">
            <span className="dot dot-success" />
            <span className="legend-name">Successful</span>
            <strong className="legend-val">{Number.isInteger(successful) ? successful : "—"}</strong>
          </div>
          <div className="coverage-legend-item">
            <span className="dot dot-failed" />
            <span className="legend-name">Failed</span>
            <strong className="legend-val">{Number.isInteger(failed) ? failed : "—"}</strong>
          </div>
          <div className="coverage-legend-item">
            <span className="dot dot-timedout" />
            <span className="legend-name">Timed out</span>
            <strong className="legend-val">{Number.isInteger(timedOut) ? timedOut : "—"}</strong>
          </div>
          <div className="coverage-legend-item">
            <span className="dot dot-skipped" />
            <span className="legend-name">Skipped</span>
            <strong className="legend-val">{Number.isInteger(skipped) ? skipped : "—"}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

function GlobalSearch({ onNavigate }) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [targetResults, setTargetResults] = useState([]);
  const [scanResults, setScanResults] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const searchRef = useRef(null);
  const inputRef = useRef(null);

  const staticTools = [
    { id: "nmap", name: "Nmap", purpose: "Network discovery & port scanning", path: "/tools" },
    { id: "subfinder", name: "Subfinder", purpose: "Passive subdomain enumeration", path: "/tools" },
    { id: "httpx", name: "HTTPX", purpose: "Web service probing & tech detection", path: "/tools" },
    { id: "whatweb", name: "WhatWeb", purpose: "Web technology fingerprinting", path: "/tools" },
    { id: "nuclei", name: "Nuclei", purpose: "Targeted vulnerability template scanner", path: "/tools" },
    { id: "sslyze", name: "SSLyze", purpose: "TLS / SSL configuration analyzer", path: "/tools" },
    { id: "wapiti", name: "Wapiti", purpose: "Web application vulnerability crawler", path: "/tools" },
    { id: "gitleaks", name: "GitLeaks", purpose: "Secret & credential detector in code", path: "/tools" },
    { id: "trivy", name: "Trivy", purpose: "Container & filesystem vulnerability scanner", path: "/tools" },
  ];

  const quickNav = [
    { name: "Overview Dashboard", path: "/" },
    { name: "New Assessment", path: "/new" },
    { name: "Authorized Targets", path: "/targets" },
    { name: "Scan History", path: "/history" },
    { name: "Tool Integrations", path: "/tools" },
    { name: "Audit Trail", path: "/audit" },
    { name: "Evidence Locker", path: "/evidence" },
    { name: "Settings & Preferences", path: "/settings" },
    { name: "Help & Documentation", path: "/help" },
  ];

  useEffect(() => {
    if (!query.trim() || query.trim().length < 2) {
      setTargetResults([]);
      setScanResults([]);
      setLoading(false);
      return;
    }
    const q = query.trim().toLowerCase();
    setLoading(true);
    let active = true;

    Promise.allSettled([
      api.get(`/api/targets?search=${encodeURIComponent(q)}`),
      api.get("/api/scans?limit=25"),
    ]).then(([targetsRes, scansRes]) => {
      if (!active) return;
      setLoading(false);
      if (targetsRes.status === "fulfilled" && Array.isArray(targetsRes.value.data?.data)) {
        setTargetResults(targetsRes.value.data.data.slice(0, 4));
      } else {
        setTargetResults([]);
      }

      if (scansRes.status === "fulfilled" && Array.isArray(scansRes.value.data?.data)) {
        const matches = scansRes.value.data.data.filter(
          (s) =>
            s.target?.toLowerCase().includes(q) ||
            s.id?.toLowerCase().includes(q) ||
            s.profile?.toLowerCase().includes(q) ||
            s.state?.toLowerCase().includes(q),
        );
        setScanResults(matches.slice(0, 4));
      } else {
        setScanResults([]);
      }
    });

    return () => {
      active = false;
    };
  }, [query]);

  useEffect(() => {
    function handleClickOutside(e) {
      if (searchRef.current && !searchRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const q = query.trim().toLowerCase();
  const filteredTools = q
    ? staticTools.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.purpose.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q),
      )
    : [];

  const filteredNav = q
    ? quickNav.filter((n) => n.name.toLowerCase().includes(q))
    : [];

  const allItems = [
    ...filteredTools.map((t) => ({ type: "tool", title: t.name, subtitle: t.purpose, path: t.path })),
    ...targetResults.map((t) => ({
      type: "target",
      title: t.name,
      subtitle: (t.scope_domains || []).slice(0, 2).join(", ") || t.owner_organization,
      path: "/targets",
    })),
    ...scanResults.map((s) => ({
      type: "scan",
      title: `${s.target} (${s.id.slice(0, 8)})`,
      subtitle: `${s.profile} · ${s.state} · ${date(s.created_at)}`,
      path: `/scan/${s.id}`,
    })),
    ...filteredNav.map((n) => ({ type: "page", title: n.name, subtitle: "Page navigation", path: n.path })),
  ];

  const handleKeyDown = (e) => {
    if (e.key === "Escape") {
      setOpen(false);
      inputRef.current?.blur();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setSelectedIndex((prev) => (prev < allItems.length - 1 ? prev + 1 : 0));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      setOpen(true);
      setSelectedIndex((prev) => (prev > 0 ? prev - 1 : allItems.length - 1));
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      if (selectedIndex >= 0 && selectedIndex < allItems.length) {
        const item = allItems[selectedIndex];
        onNavigate(item.path);
        setOpen(false);
        setQuery("");
      } else if (allItems.length > 0) {
        onNavigate(allItems[0].path);
        setOpen(false);
        setQuery("");
      } else if (query.trim()) {
        onNavigate("/history");
        setOpen(false);
      }
    }
  };

  return (
    <div className="topbar-search" ref={searchRef}>
      <Search size={15} />
      <input
        ref={inputRef}
        type="text"
        aria-label="Quick search"
        placeholder="Search scans, targets, or tools..."
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
          setSelectedIndex(-1);
        }}
        onFocus={() => {
          if (query.trim().length >= 2) setOpen(true);
        }}
        onKeyDown={handleKeyDown}
      />
      {query && (
        <button
          type="button"
          className="search-clear-btn"
          aria-label="Clear search"
          onClick={() => {
            setQuery("");
            setOpen(false);
            setSelectedIndex(-1);
            inputRef.current?.focus();
          }}
        >
          <X size={14} />
        </button>
      )}

      {open && query.trim().length >= 2 && (
        <div className="search-results-dropdown" role="listbox">
          {loading && (
            <div className="search-result-empty">
              <RefreshCw size={14} className="spin" style={{ marginRight: "6px" }} />
              Searching assessment workspace…
            </div>
          )}

          {!loading && allItems.length === 0 && (
            <div className="search-result-empty">
              No results found for &ldquo;{query}&rdquo;.
            </div>
          )}

          {!loading && filteredTools.length > 0 && (
            <div>
              <div className="search-category-title">Tools ({filteredTools.length})</div>
              {filteredTools.map((t, i) => (
                <button
                  type="button"
                  key={t.id}
                  className={`search-result-item ${selectedIndex === i ? "highlighted" : ""}`}
                  onClick={() => {
                    onNavigate(t.path);
                    setOpen(false);
                    setQuery("");
                  }}
                >
                  <div className="search-result-main">
                    <strong>{t.name}</strong>
                    <small>{t.purpose}</small>
                  </div>
                  <Layers size={14} className="subtle" />
                </button>
              ))}
            </div>
          )}

          {!loading && targetResults.length > 0 && (
            <div>
              <div className="search-category-title">Authorized Targets ({targetResults.length})</div>
              {targetResults.map((t, i) => {
                const idx = filteredTools.length + i;
                return (
                  <button
                    type="button"
                    key={t.id}
                    className={`search-result-item ${selectedIndex === idx ? "highlighted" : ""}`}
                    onClick={() => {
                      onNavigate("/targets");
                      setOpen(false);
                      setQuery("");
                    }}
                  >
                    <div className="search-result-main">
                      <strong>{t.name}</strong>
                      <small>{(t.scope_domains || []).slice(0, 3).join(", ")} · {t.owner_organization}</small>
                    </div>
                    <Target size={14} className="subtle" />
                  </button>
                );
              })}
            </div>
          )}

          {!loading && scanResults.length > 0 && (
            <div>
              <div className="search-category-title">Saved Scans ({scanResults.length})</div>
              {scanResults.map((s, i) => {
                const idx = filteredTools.length + targetResults.length + i;
                return (
                  <button
                    type="button"
                    key={s.id}
                    className={`search-result-item ${selectedIndex === idx ? "highlighted" : ""}`}
                    onClick={() => {
                      onNavigate(`/scan/${s.id}`);
                      setOpen(false);
                      setQuery("");
                    }}
                  >
                    <div className="search-result-main">
                      <strong>{s.target} ({s.id.slice(0, 8)})</strong>
                      <small className="capitalize">{s.profile} · {s.state} · {date(s.created_at)}</small>
                    </div>
                    <ArrowUpRight size={14} className="subtle" />
                  </button>
                );
              })}
            </div>
          )}

          {!loading && filteredNav.length > 0 && (
            <div>
              <div className="search-category-title">Navigation</div>
              {filteredNav.map((n, i) => {
                const idx = filteredTools.length + targetResults.length + scanResults.length + i;
                return (
                  <button
                    type="button"
                    key={n.path}
                    className={`search-result-item ${selectedIndex === idx ? "highlighted" : ""}`}
                    onClick={() => {
                      onNavigate(n.path);
                      setOpen(false);
                      setQuery("");
                    }}
                  >
                    <div className="search-result-main">
                      <strong>{n.name}</strong>
                      <small>{n.path}</small>
                    </div>
                    <ChevronRight size={14} className="subtle" />
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ProfileMenu({ currentUser, onLogout, onNavigate }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    function handleKeyDown(e) {
      if (e.key === "Escape") {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
      document.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  const initial = (currentUser ? currentUser.charAt(0) : "A").toUpperCase();

  return (
    <div className="profile-menu-container" ref={menuRef}>
      <button
        type="button"
        className="topbar-user-avatar-btn"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label="User account menu"
        title={currentUser || "Administrator"}
        onClick={() => setOpen((prev) => !prev)}
      >
        {initial}
      </button>
      {open && (
        <div className="profile-dropdown" role="menu" aria-label="Account options">
          <div className="profile-dropdown-header">
            <div className="profile-dropdown-avatar">{initial}</div>
            <div className="profile-dropdown-info">
              <strong>{currentUser || "Administrator"}</strong>
              <small>Local administrator</small>
            </div>
          </div>
          <div className="profile-dropdown-divider" />
          <button
            type="button"
            className="profile-dropdown-item"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onNavigate("/settings");
            }}
          >
            <Settings size={15} />
            <span>Settings &amp; preferences</span>
          </button>
          <button
            type="button"
            className="profile-dropdown-item"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onNavigate("/help");
            }}
          >
            <BookOpen size={15} />
            <span>Help &amp; documentation</span>
          </button>
          <div className="profile-dropdown-divider" />
          <button
            type="button"
            className="profile-dropdown-item profile-dropdown-logout"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <LogOut size={15} />
            <span>Log out</span>
          </button>
        </div>
      )}
    </div>
  );
}

function ChangePasswordCard() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const minLength = newPassword.length >= 8;
  const passwordsMatch = newPassword.length > 0 && newPassword === confirmPassword;
  const canSubmit = currentPassword && minLength && passwordsMatch && !busy;

  function handleReset() {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setError("");
    setSuccess("");
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!currentPassword) {
      setError("Please enter your current password.");
      return;
    }
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match.");
      return;
    }

    setBusy(true);
    try {
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      setSuccess("Password changed successfully. Other active sessions have been terminated.");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="settings-card settings-card-password">
      <h3><KeyRound size={17} /> Change Password</h3>
      <p className="settings-card-subtitle muted" style={{ fontSize: "13px", margin: "4px 0 16px" }}>
        Update your administrator credentials. All other active sessions will be invalidated for security.
      </p>

      {error && <div className="error-box" role="alert" style={{ marginBottom: "12px", padding: "8px 12px", borderRadius: "6px" }}>{error}</div>}
      {success && <div className="success-box" role="status" style={{ marginBottom: "12px", padding: "8px 12px", borderRadius: "6px", background: "var(--ui-success-bg, #f0fdf4)", color: "var(--ui-success-text, #166534)", border: "1px solid var(--ui-success-border, #bbf7d0)" }}>{success}</div>}

      <form onSubmit={handleSubmit} className="password-change-form">
        <div className="form-group" style={{ marginBottom: "12px" }}>
          <label htmlFor="current-password" style={{ display: "block", marginBottom: "4px", fontSize: "13px", fontWeight: "600" }}>Current Password</label>
          <div className="password-input-wrap" style={{ position: "relative", display: "flex", alignItems: "center" }}>
            <input
              id="current-password"
              type={showCurrent ? "text" : "password"}
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
              autoComplete="current-password"
              required
              disabled={busy}
              style={{ width: "100%", paddingRight: "36px" }}
            />
            <button
              type="button"
              className="password-toggle-btn"
              onClick={() => setShowCurrent(!showCurrent)}
              aria-label={showCurrent ? "Hide current password" : "Show current password"}
              tabIndex={-1}
              style={{ position: "absolute", right: "8px", background: "none", border: "none", cursor: "pointer", color: "var(--ui-muted)" }}
            >
              {showCurrent ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        <div className="form-group" style={{ marginBottom: "12px" }}>
          <label htmlFor="new-password" style={{ display: "block", marginBottom: "4px", fontSize: "13px", fontWeight: "600" }}>New Password</label>
          <div className="password-input-wrap" style={{ position: "relative", display: "flex", alignItems: "center" }}>
            <input
              id="new-password"
              type={showNew ? "text" : "password"}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
              required
              disabled={busy}
              style={{ width: "100%", paddingRight: "36px" }}
            />
            <button
              type="button"
              className="password-toggle-btn"
              onClick={() => setShowNew(!showNew)}
              aria-label={showNew ? "Hide new password" : "Show new password"}
              tabIndex={-1}
              style={{ position: "absolute", right: "8px", background: "none", border: "none", cursor: "pointer", color: "var(--ui-muted)" }}
            >
              {showNew ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        <div className="form-group" style={{ marginBottom: "12px" }}>
          <label htmlFor="confirm-password" style={{ display: "block", marginBottom: "4px", fontSize: "13px", fontWeight: "600" }}>Confirm New Password</label>
          <div className="password-input-wrap" style={{ position: "relative", display: "flex", alignItems: "center" }}>
            <input
              id="confirm-password"
              type={showConfirm ? "text" : "password"}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-enter new password"
              autoComplete="new-password"
              required
              disabled={busy}
              style={{ width: "100%", paddingRight: "36px" }}
            />
            <button
              type="button"
              className="password-toggle-btn"
              onClick={() => setShowConfirm(!showConfirm)}
              aria-label={showConfirm ? "Hide confirm password" : "Show confirm password"}
              tabIndex={-1}
              style={{ position: "absolute", right: "8px", background: "none", border: "none", cursor: "pointer", color: "var(--ui-muted)" }}
            >
              {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        <div className="password-requirements" style={{ margin: "10px 0 16px", padding: "10px 12px", background: "var(--ui-surface)", borderRadius: "6px", fontSize: "12px" }}>
          <span style={{ fontWeight: "600", display: "block", marginBottom: "6px", color: "var(--ui-text)" }}>Password Policy:</span>
          <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: "4px" }}>
            <li style={{ display: "flex", alignItems: "center", gap: "6px", color: minLength ? "var(--ui-success-text, #16a34a)" : "var(--ui-muted)" }}>
              {minLength ? <Check size={13} /> : <span style={{ width: "13px", textAlign: "center" }}>&bull;</span>}
              <span>At least 8 characters long</span>
            </li>
            <li style={{ display: "flex", alignItems: "center", gap: "6px", color: passwordsMatch ? "var(--ui-success-text, #16a34a)" : "var(--ui-muted)" }}>
              {passwordsMatch ? <Check size={13} /> : <span style={{ width: "13px", textAlign: "center" }}>&bull;</span>}
              <span>Passwords match</span>
            </li>
          </ul>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "16px" }}>
          <button
            type="button"
            className="secondary"
            onClick={handleReset}
            disabled={busy || (!currentPassword && !newPassword && !confirmPassword)}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="primary"
            disabled={!canSubmit}
          >
            {busy ? "Saving…" : "Save Password"}
          </button>
        </div>
      </form>
    </section>
  );
}

function SettingsPage({ theme, onToggleTheme, currentUser }) {
  return (
    <>
      <Heading eyebrow="WORKSPACE CONFIGURATION" title="Settings & preferences">
        Manage application preferences, authentication session parameters, operational boundaries, and security credentials.
      </Heading>
      <div className="settings-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "20px", alignItems: "start" }}>
        <section className="settings-card">
          <h3><Sun size={17} /> Appearance &amp; Display</h3>
          <div className="settings-row">
            <div>
              <span className="settings-label">Color Theme</span>
              <small className="muted">Toggle between dark operations aesthetic and eye-friendly light mode</small>
            </div>
            <button
              type="button"
              className="secondary"
              onClick={onToggleTheme}
              style={{ minHeight: "34px", padding: "6px 12px", display: "inline-flex", alignItems: "center", gap: "6px" }}
            >
              {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
              <span className="capitalize">{theme} mode</span>
            </button>
          </div>
          <div className="settings-row">
            <div>
              <span className="settings-label">Interface Layout</span>
              <small className="muted">Responsive cybersecurity SaaS dashboard</small>
            </div>
            <span className="settings-val">Adaptive grid</span>
          </div>
        </section>

        <section className="settings-card">
          <h3><ShieldCheck size={17} /> Session &amp; Security</h3>
          <div className="settings-row">
            <div>
              <span className="settings-label">Active Operator</span>
              <small className="muted">Current authenticated administrator</small>
            </div>
            <span className="settings-val"><strong>{currentUser || "Administrator"}</strong></span>
          </div>
          <div className="settings-row">
            <div>
              <span className="settings-label">Session Protection</span>
              <small className="muted">HttpOnly SameSite=Strict cookie + CSRF rotation</small>
            </div>
            <span className="settings-val" style={{ color: "var(--ui-success-text)" }}>Enforced</span>
          </div>
          <div className="settings-row">
            <div>
              <span className="settings-label">Scope Enforcement</span>
              <small className="muted">Exact-host allowlist and target authorizations</small>
            </div>
            <span className="settings-val" style={{ color: "var(--ui-success-text)" }}>Strict allowlist</span>
          </div>
        </section>

        <section className="settings-card">
          <h3><Layers size={17} /> Assessment Framework</h3>
          <div className="settings-row">
            <div>
              <span className="settings-label">Integrated Tools</span>
              <small className="muted">Backend scanners and analyzers</small>
            </div>
            <span className="settings-val">9 security engines</span>
          </div>
          <div className="settings-row">
            <div>
              <span className="settings-label">Evidence Integrity</span>
              <small className="muted">Cryptographic SHA-256 evidence hashing</small>
            </div>
            <span className="settings-val" style={{ color: "var(--ui-success-text)" }}>Active</span>
          </div>
          <div className="settings-row">
            <div>
              <span className="settings-label">Audit History</span>
              <small className="muted">Append-only security audit events</small>
            </div>
            <span className="settings-val" style={{ color: "var(--ui-success-text)" }}>Append-only</span>
          </div>
        </section>

        <ChangePasswordCard />
      </div>
    </>
  );
}

function HelpPage() {
  const tools = [
    ["Nmap", "Network discovery & comprehensive port scanning", "Network"],
    ["Subfinder", "Passive subdomain enumeration for domain scopes", "Discovery"],
    ["HTTPX", "Fast HTTP service probing & technology detection", "Web"],
    ["WhatWeb", "Web application and CMS fingerprinting", "Fingerprint"],
    ["Nuclei", "Targeted CVE and security misconfiguration templates", "Vulnerability"],
    ["SSLyze", "In-depth TLS/SSL certificate and cipher suite audit", "Crypto / TLS"],
    ["Wapiti", "Targeted web application vulnerability auditing", "Web Audit"],
    ["GitLeaks", "Static credential and API key secret scanner", "Source / Code"],
    ["Trivy", "Container and filesystem vulnerability scanner", "Filesystem"],
  ];

  return (
    <>
      <Heading eyebrow="DOCUMENTATION & GUIDELINES" title="Help & documentation">
        Reference documentation, assessment pipelines, legal scope requirements, and security guidelines.
      </Heading>
      <div className="help-grid">
        <section className="help-card" style={{ gridColumn: "1 / -1" }}>
          <h3><Layers size={17} /> Assessment Pipeline Architecture</h3>
          <p className="muted" style={{ fontSize: "12px", lineHeight: "1.6", marginBottom: "16px" }}>
            PATROLMAN executes multi-stage vulnerability assessments following strict prerequisite pipelines. Web scanners (Nuclei, SSLyze, Wapiti) require preliminary network port discovery and HTTP service probing before dispatch.
          </p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Category</th>
                  <th>Purpose &amp; Scope Requirements</th>
                </tr>
              </thead>
              <tbody>
                {tools.map(([name, desc, cat]) => (
                  <tr key={name}>
                    <td><strong>{name}</strong></td>
                    <td><span className="capitalize">{cat}</span></td>
                    <td className="muted">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="help-card">
          <h3><ShieldCheck size={17} /> Target Authorization &amp; Scope Rules</h3>
          <ul style={{ fontSize: "12px", lineHeight: "1.7", color: "var(--ui-muted)", paddingLeft: "18px" }}>
            <li>Exact-match allowlist: Assessments can only be executed against approved, in-scope domains or IP addresses.</li>
            <li>Policy restrictions: Tools categorized under prohibited methods for a target are blocked automatically.</li>
            <li>Prerequisite dependency: Skipped tools reflect unsatisfied dependencies, not errors.</li>
            <li>Evidence retention: Every raw output is hashed with SHA-256 and stored in the Evidence Locker.</li>
          </ul>
        </section>

        <section className="help-card">
          <h3><Clock size={17} /> Quick Navigation &amp; Shortcuts</h3>
          <ul style={{ fontSize: "12px", lineHeight: "1.7", color: "var(--ui-muted)", paddingLeft: "18px" }}>
            <li><a href="#/new" className="scope-target-link">New Assessment</a> — Dispatch a scan across authorized targets</li>
            <li><a href="#/targets" className="scope-target-link">Authorized Targets</a> — Register and inspect authorized hosts</li>
            <li><a href="#/tools" className="scope-target-link">Tool Integrations</a> — Verify installation and runtime prerequisites</li>
            <li><a href="#/history" className="scope-target-link">Scan History</a> — Revisit saved records and run diff comparisons</li>
            <li><a href="#/audit" className="scope-target-link">Audit Trail</a> — Inspect append-only operator activity</li>
            <li><a href="#/evidence" className="scope-target-link">Evidence Locker</a> — Download cryptographically verified raw artifacts</li>
          </ul>
        </section>
      </div>
    </>
  );
}

function Dashboard() {
  const r = useLoad("/api/dashboard", 4000),
    d = r.data;
  const totalScans = d?.total_scans || 0;
  const completedScans = d?.states?.completed || 0;
  const successRate = totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0;

  return (
    <>
      <Heading
        eyebrow="YOUR SECURITY WORKSPACE"
        title="Assessment overview"
        action={
          <div className="overview-header-actions">
            <button
              type="button"
              className="secondary refresh-btn"
              onClick={r.reload}
              disabled={r.loading}
              title="Refresh assessment metrics"
            >
              <RefreshCw size={15} className={r.loading ? "spin" : ""} />
              {r.loading ? "Refreshing…" : "Refresh data"}
            </button>
            <button type="button" className="primary" onClick={() => go("/new")}>
              <Plus size={18} />
              New assessment
            </button>
          </div>
        }
      >
        A clear view of your scans, findings, and assessment coverage.
      </Heading>
      <ErrorBox message={r.error} />
      {r.loading && !d ? (
        <div className="loading">Loading assessment data…</div>
      ) : (
        d && (
          <>
            <div className="metrics dashboard-metrics">
              {[
                [
                  "Total assessments",
                  d.total_scans,
                  Layers,
                  "All saved scan records",
                ],
                [
                  "Successfully completed",
                  d.states?.completed || 0,
                  CheckCircle2,
                  totalScans > 0 ? `${successRate}% success rate` : "Every selected tool completed",
                ],
                [
                  "Partial coverage",
                  d.states?.completed_with_errors || 0,
                  AlertTriangle,
                  "One or more tools did not complete",
                ],
                [
                  "In progress",
                  (d.states?.running || 0) + (d.states?.queued || 0),
                  Activity,
                  "Running and queued",
                ],
                [
                  "Failed or cancelled",
                  (d.states?.failed || 0) + (d.states?.cancelled || 0),
                  Ban,
                  `${d.states?.failed || 0} failed · ${d.states?.cancelled || 0} cancelled`,
                ],
                [
                  "Potential findings",
                  d.total_findings,
                  ShieldCheck,
                  "Manual validation required",
                ],
              ].map(([label, value, Icon, note]) => (
                <article className="metric" key={label}>
                  <div className="metric-header">
                    <span>{label}</span>
                    <Icon size={17} />
                  </div>
                  <strong>{value}</strong>
                  <small>{note}</small>
                </article>
              ))}
            </div>

            <div className="overview-grid">
              {/* Card 1: Finding distribution */}
              <section className="panel finding-panel">
                <div className="panel-title">
                  <div className="panel-title-text">
                    <ShieldCheck size={18} />
                    <h2>Finding distribution</h2>
                  </div>
                  <span className="subtle">BY SEVERITY</span>
                </div>
                <div className="distribution">
                  <div className="finding-total">
                    <strong>{d.total_findings}</strong>
                    <span>potential findings</span>
                    <p>
                      {d.total_findings
                        ? "Prioritize, investigate, validate."
                        : "Start an assessment to collect evidence."}
                    </p>
                  </div>
                  <div className="bars">
                    {severities.map((s) => (
                      <div className="severity-row" key={s}>
                        <span className="capitalize">
                          <i className={"severity-dot " + s} />
                          {s}
                        </span>
                        <div className="bar-track">
                          <div
                            className={s}
                            style={{
                              width: `${(100 * (d.severities[s] || 0)) / Math.max(1, d.total_findings)}%`,
                            }}
                          />
                        </div>
                        <b>{d.severities[s] || 0}</b>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {/* Card 2: Tool execution coverage with donut chart */}
              <section className="panel coverage-panel">
                <div className="panel-title">
                  <div className="panel-title-text">
                    <Layers size={18} />
                    <h2>Tool execution coverage</h2>
                  </div>
                  <a className="text-link" href="#/tools">
                    View tool integrations <ArrowUpRight size={14} />
                  </a>
                </div>
                <p className="panel-desc">
                  Counts reflect saved tool executions. A started tool is not necessarily a successful check.
                </p>
                <ToolCoverageDonut coverage={d.coverage} />
              </section>

              {/* Card 3: Recent assessments */}
              <section className="panel recent-panel">
                <div className="panel-title">
                  <div className="panel-title-text">
                    <Clock size={18} />
                    <h2>Recent assessments</h2>
                  </div>
                  <a className="text-link" href="#/history">
                    View all <ArrowRight size={14} />
                  </a>
                </div>
                <p className="panel-desc">
                  Your latest activity, backed by saved scan records.
                </p>
                {d.recent.length ? (
                  <ScanTable scans={d.recent} compact={true} />
                ) : (
                  <div className="dashboard-empty">
                    <Empty title="Your first assessment starts here">
                      Create a scan for an authorized target. Results and history will appear here.
                    </Empty>
                    <button className="primary" onClick={() => go("/new")}>
                      <Plus size={17} /> Create first assessment
                    </button>
                  </div>
                )}
              </section>
            </div>
          </>
        )
      )}
    </>
  );
}
const TOOL_METHOD_MAP = {
  nmap: ["port_scan"],
  httpx: ["web_service_discovery"],
  whatweb: ["web_service_discovery"],
  subfinder: ["web_service_discovery"],
  sslyze: ["tls_audit"],
  nuclei: ["vulnerability_check"],
  // Wapiti crawls and attacks within the exact base-URL scope, so a target
  // that prohibits active crawling is blocked from running it.
  wapiti: ["vulnerability_check", "active_crawl"],
  gitleaks: ["local_scan"],
  trivy: ["local_scan"],
};

function NewScan() {
  const profiles = useLoad("/api/profiles"),
    inventory = useLoad("/api/tools"),
    targetsResp = useLoad("/api/targets?page_size=100");
  const registeredTargets = Array.isArray(targetsResp.data)
    ? targetsResp.data
    : Array.isArray(targetsResp.data?.data)
      ? targetsResp.data.data
      : [];
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const selectedTarget = registeredTargets.find((t) => t.id === selectedTargetId) || null;
  const [editingTargetModalId, setEditingTargetModalId] = useState(null);

  const [target, setTarget] = useState(""),
    [profile, setProfile] = useState("quick"),
    [tools, setTools] = useState([]),
    [authorized, setAuthorized] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [key, setKey] = useState(() => crypto.randomUUID());

  // Auto-match custom host against registered targets if none explicitly chosen
  const trimmedTarget = target.trim();
  const extractedHost = extractTargetHost(trimmedTarget);
  const autoMatchedTarget = !selectedTarget && trimmedTarget
    ? registeredTargets.find((t) => {
        const domains = [...(t.scope_domains || []), ...(t.explicit_subdomains || [])];
        return domains.some((dom) => {
          const cleanDom = (dom.endsWith("/32") || dom.endsWith("/128")) ? dom.slice(0, dom.lastIndexOf("/")) : dom;
          return dom === trimmedTarget || cleanDom === trimmedTarget || dom === extractedHost || cleanDom === extractedHost;
        });
      }) || null
    : null;
  const effectiveTarget = selectedTarget || autoMatchedTarget;

  function getToolEligibility(name, targetObj = effectiveTarget) {
    const invTool = inventory.data?.find((x) => x.name === name);
    const requiredCategories = TOOL_METHOD_MAP[name] || [];

    // 1. Target prohibitions (fail-closed)
    if (targetObj) {
      const prohibitedMethods = targetObj.prohibited_methods || [];
      const blockedCats = requiredCategories.filter((c) => prohibitedMethods.includes(c));
      if (blockedCats.length > 0) {
        return {
          status: "not_permitted",
          blocked: true,
          label: "Not Permitted",
          reason: `Target explicitly prohibits method '${blockedCats.join(", ")}'.`,
        };
      }

      // 2. Target permissions
      const permittedMethods = targetObj.permitted_methods || [];
      if (permittedMethods.length > 0) {
        const hasPermitted = requiredCategories.some((c) => permittedMethods.includes(c));
        if (!hasPermitted) {
          return {
            status: "not_permitted",
            blocked: true,
            label: "Not Permitted",
            reason: `Target lacks '${requiredCategories.join(", ")}' permission (permits: ${permittedMethods.join(", ")}).`,
          };
        }
      }
    }

    // 3. Tool installation / inventory checks
    if (invTool) {
      if (invTool.status === "missing") {
        return {
          status: "unavailable",
          blocked: true,
          label: "Unavailable",
          reason: invTool.reason || "Scanner executable not found on server.",
        };
      }
      if (invTool.status === "configuration_required" && name !== "gitleaks") {
        return {
          status: "configuration_required",
          blocked: true,
          label: "Configuration Required",
          reason: invTool.reason || "Configuration required before execution.",
        };
      }
      if (invTool.status === "version_unverified") {
        return {
          status: "version_unverified",
          blocked: false,
          label: "Version Unverified",
          reason: invTool.reason || "Scanner version could not be verified.",
        };
      }
      if (
        invTool.status === "version_check_pending" ||
        invTool.version_verification?.status === "pending_check" ||
        invTool.version_verification?.message === "Version check not requested."
      ) {
        return {
          status: "version_check_pending",
          blocked: false,
          label: "Version Check Pending",
          reason: "Fast inventory loaded; full version verification pending availability check.",
        };
      }
    }

    // 4. Wapiti safety gate & operator opt-in
    if (name === "wapiti") {
      if (invTool?.status === "disabled" || invTool?.operator_opt_in?.status === "disabled") {
        return {
          status: "blocked",
          blocked: true,
          label: "Opt-in Required",
          reason: "Requires explicit operator opt-in (AVA_WAPITI_ENABLED=true in .env).",
        };
      }
    }

    // 5. Discovery prerequisites for web tools
    if (profile !== "local") {
      if (["whatweb", "nuclei", "sslyze", "wapiti"].includes(name)) {
        if (!tools.includes("nmap")) {
          const nmapPermitted = targetObj
            ? (targetObj.permitted_methods?.length ? targetObj.permitted_methods.includes("port_scan") : true)
            : true;
          return {
            status: "needs_nmap",
            blocked: false,
            label: "Needs Nmap",
            reason: !nmapPermitted
              ? "Web checks require Nmap service discovery, but Nmap is currently not permitted by target policy."
              : "Web checks require Nmap service discovery in tool selection.",
          };
        }
        if (!tools.includes("httpx")) {
          return {
            status: "needs_httpx",
            blocked: false,
            label: "Needs httpx",
            reason: "Web checks require httpx service discovery in tool selection.",
          };
        }
      }
    }

    return {
      status: "ready",
      blocked: false,
      label: invTool?.status === "ready" ? "Ready" : invTool?.status || "Ready",
      reason: null,
    };
  }

  useEffect(() => {
    if (profiles.data && profiles.data[profile]) {
      const defaultTools = profiles.data[profile].tools || [];
      if (effectiveTarget) {
        const nmapPermitted = effectiveTarget.permitted_methods?.length
          ? effectiveTarget.permitted_methods.includes("port_scan")
          : true;
        setTools(
          defaultTools.filter((t) => {
            const elig = getToolEligibility(t, effectiveTarget);
            if (elig.blocked) return false;
            if (profile !== "local" && ["whatweb", "nuclei", "sslyze", "wapiti"].includes(t) && !nmapPermitted) {
              return false;
            }
            return true;
          })
        );
      } else {
        setTools(defaultTools);
      }
    }
  }, [profile, profiles.data, selectedTargetId, autoMatchedTarget?.id]);

  function handleSelectTarget(id) {
    setSelectedTargetId(id);
    const chosen = registeredTargets.find((t) => t.id === id);
    if (chosen) {
      const firstDomain = chosen.scope_domains?.[0] || chosen.explicit_subdomains?.[0] || "";
      if (firstDomain) {
        const cleanHost = (firstDomain.endsWith("/32") || firstDomain.endsWith("/128"))
          ? firstDomain.slice(0, firstDomain.lastIndexOf("/"))
          : firstDomain;
        const currentClean = target ? target.trim() : "";
        if (!currentClean || (!currentClean.includes(cleanHost) && !cleanHost.includes(currentClean))) {
          setTarget(cleanHost);
        }
      }
    }
    change();
  }

  function change() {
    setKey(crypto.randomUUID());
    setError("");
  }

  async function submit(e) {
    e.preventDefault();
    if (busy) return;
    const targetError = validateTargetInput(target, profile);
    if (targetError) {
      setError(targetError);
      return;
    }
    if (!authorized) {
      setError("Confirm authorization before starting.");
      return;
    }
    const finalTools = tools.filter((t) => !getToolEligibility(t, effectiveTarget).blocked);
    if (!finalTools.length) {
      setError("Select at least one permitted scanner.");
      return;
    }
    if (profile !== "local" && finalTools.some((t) => ["whatweb", "nuclei", "sslyze", "wapiti"].includes(t)) && !finalTools.includes("nmap")) {
      setError("Web assessment requires Nmap discovery in tool selection. Select Nmap or remove dependent web checks.");
      return;
    }
    if (finalTools.some((t) => ["whatweb", "nuclei", "sslyze"].includes(t)) && !finalTools.includes("httpx")) {
      setError("Web assessment requires httpx discovery in tool selection. Select httpx or remove dependent web checks.");
      return;
    }
    setBusy(true);
    try {
      const r = await api.post(
        "/api/scans",
        {
          target: target.trim(),
          profile,
          tools: finalTools,
          authorized,
          target_id: selectedTargetId || autoMatchedTarget?.id || undefined,
        },
        { headers: { "Idempotency-Key": key } },
      );
      if (r.data?.data) {
        appDataCache.set("/api/scans/" + r.data.data.id, r.data);
      }
      go("/scan/" + r.data.data.id);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const activeTools = (tools || []).filter((t) => !getToolEligibility(t, effectiveTarget).blocked);

  return (
    <>
      <Heading eyebrow="SECURITY OPERATIONS" title="Start an assessment">
        Define target scope, select a profile, verify tool eligibility, and record assessment evidence.
      </Heading>
      <ErrorBox message={profiles.error || inventory.error || targetsResp.error} />
      <form onSubmit={submit} className="new-grid">
        <section className="panel form-panel">
          {/* STEP 01 */}
          <div className="step-heading">
            <span>01</span>
            <div>
              <h2>Target Selection &amp; Scope</h2>
              <small className="muted">Choose a registered target or define a custom authorized host</small>
            </div>
          </div>

          {targetsResp.loading ? (
            <div style={{ marginBottom: "16px", fontSize: "12px", color: "var(--ui-muted)" }}>
              <RefreshCw size={12} className="spin" style={{ marginRight: "6px" }} /> Loading authorized targets...
            </div>
          ) : registeredTargets.length > 0 ? (
            <div className="target-select-wrap">
              <label htmlFor="authorized-target-select">
                <Target size={14} style={{ verticalAlign: "middle", marginRight: "6px" }} />
                Authorized Target Profile (optional)
              </label>
              <select
                id="authorized-target-select"
                className="target-select"
                value={selectedTargetId}
                onChange={(e) => handleSelectTarget(e.target.value)}
              >
                <option value="">Custom target / Exact-host allowlist</option>
                {registeredTargets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.owner_organization}) — {pretty(t.effective_status)}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="target-select-empty">
              No registered authorized targets. Using exact-host allowlist.
            </div>
          )}

          {selectedTarget && (
            <div className="target-summary-card">
              <div className="target-summary-top">
                <div>
                  <strong className="target-summary-title">{selectedTarget.name}</strong>
                  <span className="muted target-summary-org">({selectedTarget.owner_organization})</span>
                </div>
                <div className="target-summary-actions">
                  <Badge value={selectedTarget.effective_status} />
                  <Badge value={selectedTarget.target_type} />
                  <button
                    type="button"
                    className="secondary btn-edit-target"
                    onClick={() => setEditingTargetModalId(selectedTarget.id)}
                  >
                    <Edit2 size={12} /> Edit Target &amp; Permissions
                  </button>
                </div>
              </div>
              <div className="target-summary-meta">
                <span>Rate limit: <strong>{selectedTarget.rate_limit_rps} req/sec</strong></span>
                <span>Valid to: <strong>{selectedTarget.valid_to ? new Date(selectedTarget.valid_to).toLocaleDateString() : "N/A"}</strong></span>
                <span>Ref: <strong>{selectedTarget.evidence_reference}</strong></span>
              </div>
              <div className="target-summary-hosts">
                <span className="target-summary-label">Authorized hosts (click to set target):</span>
                <div className="chip-list" style={{ marginTop: "4px" }}>
                  {[...(selectedTarget.scope_domains || []), ...(selectedTarget.explicit_subdomains || [])].map((dom) => {
                    const cleanDom = (dom.endsWith("/32") || dom.endsWith("/128")) ? dom.slice(0, dom.lastIndexOf("/")) : dom;
                    return (
                      <button
                        key={dom}
                        type="button"
                        className={`chip ${target === dom || target === cleanDom ? "chip--active" : ""}`}
                        onClick={() => { setTarget(cleanDom); change(); }}
                      >
                        {dom}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="target-summary-methods">
                <span className="target-summary-label">Permitted assessment methods:</span>{" "}
                <strong>{selectedTarget.permitted_methods?.join(", ") || "All methods permitted"}</strong>
              </div>
              {selectedTarget.prohibited_methods?.length > 0 && (
                <div className="target-summary-prohibited">
                  <span className="target-summary-label">Prohibited methods:</span>{" "}
                  <strong>{selectedTarget.prohibited_methods.join(", ")}</strong>
                </div>
              )}
              {selectedTarget.excluded_scope?.length > 0 && (
                <div className="target-summary-excluded">
                  <AlertTriangle size={13} style={{ flexShrink: 0 }} />
                  <span><strong>Excluded scope (protected):</strong> {selectedTarget.excluded_scope.join(", ")}</span>
                </div>
              )}
            </div>
          )}

          <label htmlFor="target">{profile === "local" ? "Authorized local directory (on backend computer)" : "Target hostname or IP address"}</label>
          <div className="input-icon">
            <Globe size={18} />
            <input
              id="target"
              placeholder="e.g. 127.0.0.1 or an authorized domain"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                change();
              }}
              required
            />
          </div>

          {autoMatchedTarget && !selectedTarget && (
            <div className="auto-matched-notice">
              <ShieldCheck size={13} />
              <span>Host matched active authorization: <strong>{autoMatchedTarget.name}</strong> ({autoMatchedTarget.owner_organization}). Tool eligibility is validated against this scope.</span>
            </div>
          )}

          <ScopeCheckWidget host={target} profile={profile} targetId={selectedTargetId || autoMatchedTarget?.id} />
          <p className="help">
            {profile === "local" ? "Must exactly match AVA_ALLOWED_LOCAL_ROOTS. Working-tree snapshot only; links and network shares are rejected. No Git history is scanned." : "Must match the administrator’s exact-host allowlist or registered authorized scope. Canonical CIDRs (/32, /128) and service endpoints with custom ports are supported."}
          </p>

          {/* STEP 02 */}
          <div className="step-heading">
            <span>02</span>
            <div>
              <h2>Scan Profile</h2>
              <small className="muted">Select depth and scope of vulnerability checks</small>
            </div>
          </div>
          <div className="profile-grid">
            {profiles.data &&
              Object.entries(profiles.data).map(([name, v]) => (
                <button
                  key={name}
                  type="button"
                  className={"profile " + (profile === name ? "selected" : "")}
                  onClick={() => {
                    setProfile(name);
                    change();
                  }}
                >
                  <span className="radio">{profile === name && <i />}</span>
                  <strong className="capitalize">{name}</strong>
                  <small>{v.description}</small>
                </button>
              ))}
          </div>

          {/* STEP 03 */}
          <div className="step-heading">
            <span>03</span>
            <div>
              <h2>Tool Selection &amp; Eligibility</h2>
              <small className="muted">Verified against server inventory, target permissions, and safety restrictions</small>
            </div>
          </div>
          <div className="tool-choices-grid">
            {(profiles.data?.[profile]?.tools || []).map((name) => {
              const eligibility = getToolEligibility(name);
              const disabled = eligibility.blocked;
              const isChecked = tools.includes(name) && !disabled;
              return (
                <div
                  key={name}
                  className={`tool-choice-card ${disabled ? "tool-choice--disabled" : isChecked ? "tool-choice--checked" : ""} ${eligibility.status}`}
                >
                  <div className="tool-choice-header">
                    <label className="tool-choice-label">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        disabled={disabled}
                        onChange={(e) => {
                          if (disabled) return;
                          setTools(
                            e.target.checked
                              ? [...tools, name]
                              : tools.filter((x) => x !== name),
                          );
                          change();
                        }}
                      />
                      <span className="tool-choice-name">{name}</span>
                    </label>
                    <Badge value={eligibility.status} label={eligibility.label} />
                  </div>
                  <div className="tool-choice-method">
                    Method: <code>{(TOOL_METHOD_MAP[name] || []).join(", ")}</code>
                  </div>
                  {eligibility.reason && (
                    <div className={`tool-eligibility-reason ${disabled ? "reason-blocked" : "reason-warning"}`}>
                      {eligibility.reason}
                    </div>
                  )}
                  {eligibility.status === "not_permitted" && effectiveTarget && (
                    <button
                      type="button"
                      className="btn-update-permissions"
                      onClick={() => setEditingTargetModalId(effectiveTarget.id)}
                    >
                      <Edit2 size={11} style={{ marginRight: "4px" }} />
                      Update target permissions
                    </button>
                  )}
                </div>
              );
            })}
          </div>
          <p className="help" style={{ marginTop: "10px" }}>
            Unavailable or unpermitted tools are blocked from selection. Web checks require Nmap port discovery and httpx probing.
          </p>

          {/* STEP 04 */}
          <div className="step-heading">
            <span>04</span>
            <div>
              <h2>Assessment Configuration Preview</h2>
              <small className="muted">Review operational parameters before dispatch</small>
            </div>
          </div>
          <div className="assessment-preview-card">
            <div className="assessment-preview-header">
              <ShieldCheck size={16} />
              <strong>Operational Scope &amp; Parameters</strong>
            </div>
            <div className="assessment-preview-grid">
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Target</span>
                <strong className="assessment-preview-value">{normalizeEndpointPreview(target, profile)}</strong>
              </div>
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Authorization</span>
                <strong className="assessment-preview-value">{effectiveTarget ? effectiveTarget.name : "Allowlist check"}</strong>
              </div>
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Profile</span>
                <strong className="assessment-preview-value capitalize">{profile}</strong>
              </div>
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Tools ({activeTools.length})</span>
                <strong className="assessment-preview-value">{activeTools.join(", ") || "(none)"}</strong>
              </div>
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Max Rate</span>
                <strong className="assessment-preview-value">{effectiveTarget ? `${effectiveTarget.rate_limit_rps} req/s` : "Safety baseline"}</strong>
              </div>
              <div className="assessment-preview-item">
                <span className="assessment-preview-label">Pre-scan Scope</span>
                <strong className={`assessment-preview-value ${effectiveTarget ? "status-verified" : ""}`}>
                  {effectiveTarget ? "Verified" : "Allowlist check"}
                </strong>
              </div>
            </div>
          </div>

          {/* STEP 05 */}
          <div className="step-heading">
            <span>05</span>
            <div>
              <h2>Authorization Confirmation</h2>
              <small className="muted">Mandatory operator scope confirmation</small>
            </div>
          </div>
          <label className="authorization">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => {
                setAuthorized(e.target.checked);
                change();
              }}
            />
            <span>
              I own this target or have explicit permission to assess it, and
              these checks are within that authorization.
            </span>
          </label>
          <ErrorBox message={error} />

          <div className="new-assessment-actions">
            <button className="primary btn-start-assessment" disabled={busy || !profiles.data || !activeTools.length}>
              {busy ? "Creating assessment…" : "Start assessment"}
              <ArrowRight size={17} />
            </button>
          </div>
        </section>
        <section className="panel guide">
          <ShieldCheck size={28} />
          <h2>
            Purposeful checks.
            <br />
            Transparent results.
          </h2>
          <p>
            Each scan records tool availability, execution outcomes, discovered
            assets, and potential findings.
          </p>
          <div className="guide-points">
            <div>
              <Check size={16} />
              <span>Target scope is strictly verified against allowlists and authorizations</span>
            </div>
            <div>
              <Check size={16} />
              <span>Only eligible scanners permitted by target policy are executed</span>
            </div>
            <div>
              <Check size={16} />
              <span>Every finding is backed by timestamped raw tool output</span>
            </div>
          </div>
        </section>
      </form>
      {editingTargetModalId && (
        <TargetDetailsModal
          targetId={editingTargetModalId}
          startEditing={true}
          onClose={() => setEditingTargetModalId(null)}
          onRefresh={() => {
            targetsResp.reload();
          }}
        />
      )}
    </>
  );
}
const toolFilters = [
  ["all", "All"],
  ["ready", "Ready"],
  ["configuration_required", "Configuration required"],
  ["not_installed", "Not installed / not discovered"],
  ["blocked", "Blocked / failed"],
  ["unverified", "Needs verification"],
];
function toolCategory(tool) {
  const verification = tool.workflow_verification?.status;
  if (tool.status === "missing") return "not_installed";
  if (tool.status === "configuration_required") return "configuration_required";
  if (
    ["blocked", "execution_blocked", "disabled", "unknown", "failed"].includes(
      tool.status,
    ) ||
    ["failed", "timed_out"].includes(verification)
  ) {
    return "blocked";
  }
  if (tool.status === "ready" && verification === "verified") return "ready";
  return "unverified";
}
function toolStatusLabel(tool) {
  const category = toolCategory(tool);
  if (category === "ready") return "READY";
  if (category === "not_installed") return "NOT_DISCOVERED";
  if (category === "configuration_required") return "CONFIGURATION_REQUIRED";
  if (category === "blocked") {
    if (tool.workflow_verification?.status === "failed") return "VERIFICATION_FAILED";
    if (tool.workflow_verification?.status === "timed_out") return "VERIFICATION_TIMED_OUT";
    return tool.status === "disabled"
      ? "SAFETY_DISABLED"
      : tool.state || "BLOCKED";
  }
  if (
    tool.state === "VERSION_UNVERIFIED" ||
    tool.status === "version_unverified" ||
    (tool.version_verification?.status === "unverified" &&
      tool.executable_found &&
      tool.status !== "ready" &&
      tool.version_verification?.message !== "Version check not requested.")
  ) {
    return "VERSION_UNVERIFIED";
  }
  if (tool.workflow_verification?.status === "version_changed" || tool.state === "VERSION_CHANGED") {
    return "VERSION_CHANGED";
  }
  if (tool.workflow_verification?.status === "pending_check") {
    return tool.status === "ready" ? "READY" : "CHECK_PENDING";
  }
  if (tool.state === "UNVERIFIED" || category === "unverified") {
    return "NEEDS_VERIFICATION";
  }
  return tool.state || "NEEDS_VERIFICATION";
}
function toolVerificationLabel(tool) {
  const status = tool.workflow_verification?.status;
  if (status === "verified") return "Verified in assessment";
  if (status === "failed") return "Last execution failed";
  if (status === "timed_out") return "Last execution timed out";
  if (status === "version_changed") return "Version differs from last successful execution";
  if (status === "pending_check") {
    return tool.workflow_verification?.last_state
      ? `Last execution: ${pretty(tool.workflow_verification.last_state)} (check pending)`
      : "Check pending";
  }
  if (tool.workflow_verification?.last_state) {
    return `Last execution: ${pretty(tool.workflow_verification.last_state)}`;
  }
  return "No successful execution recorded";
}
function Tools() {
  // Phase 1: instant load – filesystem discovery only, no subprocess probes.
  // The shell and tool list render immediately in ~50 ms.
  const r = useLoad("/api/tools?check_versions=false");
  // Phase 2: full version probes, triggered only by the user clicking
  // "Check availability". We keep the last full result in state
  // so the grid never goes blank while a slow probe is running.
  const [checking, setChecking] = useState(false);
  const [verifiedData, setVerifiedData] = useState(null);
  const [verifyError, setVerifyError] = useState("");

  async function checkAvailability() {
    setChecking(true);
    setVerifyError("");
    try {
      const resp = await api.get("/api/tools");   // check_versions=true by default
      if (resp.data?.data) {
        setVerifiedData(resp.data.data);
      }
    } catch (e) {
      setVerifyError(errorMessage(e));
    } finally {
      setChecking(false);
    }
  }

  // Use the full-version data when available, otherwise show the fast snapshot.
  const tools = verifiedData || r.data || [];
  const [filter, setFilter] = useState("all");
  const counts = Object.fromEntries(
    toolFilters.map(([key]) => [
      key,
      key === "all" ? tools.length : tools.filter((tool) => toolCategory(tool) === key).length,
    ]),
  );
  const visibleTools = tools.filter(
    (tool) => filter === "all" || toolCategory(tool) === filter,
  );

  return (
    <>
      <Heading
        eyebrow="INTEGRATION STATUS"
        title="Your assessment toolkit"
        action={
          <button className="secondary" onClick={checkAvailability} disabled={checking} id="tools-check-availability-btn">
            <RefreshCw size={16} className={checking ? "spin" : ""} />
            {checking ? "Checking…" : "Check availability"}
          </button>
        }
      >
        Review backend discovery, runtime requirements, and the latest genuine
        assessment evidence separately for each integration.
      </Heading>
      <ErrorBox message={r.error} />
      <ErrorBox message={verifyError} id="tools-verify-error" />
      <div className="tool-summary-grid" aria-label="Tool status summary">
        {toolFilters.slice(1).map(([key, label]) => (
          <div className="tool-summary-card" key={key}>
            <span>{label}</span>
            <strong>{counts[key]}</strong>
          </div>
        ))}
      </div>
      <div className="tool-filter-bar" role="group" aria-label="Filter integrations">
        {toolFilters.map(([key, label]) => (
          <button
            className={filter === key ? "active" : ""}
            aria-pressed={filter === key}
            key={key}
            onClick={() => setFilter(key)}
          >
            {label} <span>{counts[key]}</span>
          </button>
        ))}
      </div>
      {r.loading ? (
        <div className="loading" role="status" aria-label="Loading tool inventory">Checking tools…</div>
      ) : r.data && tools.length === 0 ? (
        <Empty title="No tool inventory available">
          The backend did not return any integrations.
        </Empty>
      ) : (
        <div className="integration-grid">
          {visibleTools.map((t) => (
            <section className="panel integration tool-card" key={t.name}>
              <div className="tool-card-head">
                <span className="tool-symbol">
                  <Terminal size={21} />
                </span>
                <Badge value={toolStatusLabel(t)} />
              </div>
              <h2>{t.name}</h2>
              <p className="tool-purpose" title={t.purpose}>{t.purpose}</p>
              <p className="tool-reason">
                {t.status === "missing"
                  ? "The backend could not resolve the executable or required runtime; it may be installed outside its configured path."
                  : t.status === "configuration_required"
                    ? t.reason || "The executable path or required runtime configuration needs attention."
                    : t.workflow_verification?.status === "failed"
                      ? "The latest recorded assessment execution did not complete successfully."
                      : t.workflow_verification?.status === "version_changed"
                        ? "The current executable version differs from the last successful assessment."
                        : toolCategory(t) === "unverified"
                          ? "A successful assessment and result-parsing record for this version has not been confirmed."
                          : t.reason}
              </p>
              <div className="tool-facts">
                <div className="tool-fact">
                  <span>Installation</span>
                  <strong>{t.executable_found ? "Found by backend" : "Not discovered"}</strong>
                </div>
                <div className="tool-fact">
                  <span>Runtime / configuration</span>
                  <strong>{pretty(t.runtime_configuration?.status || "not reported")}</strong>
                </div>
                <div className="tool-fact">
                  <span>Version verification</span>
                  <strong>
                    {t.version
                      ? `Verified (${t.version})`
                      : t.version_verification?.message === "Version check not requested."
                        ? "Check not requested"
                        : t.version_verification?.status === "unverified"
                          ? "Unverified"
                          : t.executable_found
                            ? "Version unverified"
                            : "Not installed"}
                  </strong>
                </div>
                <div className="tool-fact">
                  <span>Workflow verification</span>
                  <strong>{toolVerificationLabel(t)}</strong>
                </div>
              </div>

              {Array.isArray(t.capabilities) && t.capabilities.length > 0 && (
                <ul
                  className="tool-capabilities"
                  aria-label={`${t.name} capabilities`}
                >
                  {t.capabilities.map((capability) => (
                    <li key={capability}>{capability}</li>
                  ))}
                </ul>
              )}
              <details className="tool-details">
                <summary>Setup and verification details</summary>
                <div className="tool-details-content">
                  <div>
                    <strong>Backend status</strong>
                    <p>{t.reason || "No additional status detail was supplied."}</p>
                  </div>
                  {t.version_verification && (
                    <div>
                      <strong>Version verification</strong>
                      <p>{t.version_verification.message}</p>
                    </div>
                  )}
                  {t.runtime_configuration && (
                    <div>
                      <strong>Runtime configuration</strong>
                      <p>{t.runtime_configuration.message}</p>
                    </div>
                  )}
                  {t.workflow_verification && (
                    <div>
                      <strong>Latest workflow evidence</strong>
                      <p>
                        {toolVerificationLabel(t)}
                        {t.workflow_verification.last_checked_at
                          ? ` · ${date(t.workflow_verification.last_checked_at)}`
                          : ""}
                      </p>
                    </div>
                  )}
                  {t.integrity && (
                    <div>
                      <strong>
                        Binary integrity · {pretty(t.integrity.status)}
                      </strong>
                      <p>
                        {t.integrity.message}
                        {t.integrity.status === "verified" && t.integrity.actual
                          ? ` SHA-256 prefix: ${t.integrity.actual.slice(0, 12)}…`
                          : ""}
                      </p>
                    </div>
                  )}
                  {t.operator_opt_in && (
                    <div>
                      <strong>
                        Operator opt-in · {pretty(t.operator_opt_in.status)}
                      </strong>
                      <p>
                        {t.operator_opt_in.message}
                        {t.operator_opt_in.variable
                          ? ` Variable: ${t.operator_opt_in.variable}`
                          : ""}
                      </p>
                    </div>
                  )}
                  {t.safety_restrictions && (
                    <div>
                      <strong>Safety restrictions</strong>
                      <p>{t.safety_restrictions}</p>
                    </div>
                  )}
                  {t.setup && (
                    <div>
                      <strong>Setup instructions</strong>
                      <p>{t.setup}</p>
                    </div>
                  )}
                </div>
              </details>
            </section>
          ))}
          {!visibleTools.length && (
            <div className="panel tool-filter-empty">
              <h2>No integrations match this filter</h2>
              <p>Choose another status filter to review the backend inventory.</p>
            </div>
          )}
        </div>
      )}
      <div className="note" role="note" aria-label="Tool readiness notice">
        <Info size={18} className="note-icon" aria-hidden="true" />
        <div className="note-text">
          <strong className="note-title">Readiness verification: </strong>
          "Ready" requires a successful assessment execution and result parse for
          the current verified version. Installation, configuration, and prior
          workflow evidence are separate. Wapiti remains disabled by default; when
          explicitly enabled it runs a bounded crawl of the exact base URL with an
          explicit, conservative module list and never an implicit one.
        </div>
      </div>
    </>
  );
}
function Pagination({ page, total, size = 20, onChange }) {
  return (
    <div className="pagination">
      <span>
        {total} records · Page {page}
      </span>
      <div>
        <button
          aria-label="Previous page"
          disabled={page === 1}
          onClick={() => onChange(page - 1)}
        >
          <ChevronLeft size={17} />
        </button>
        <button
          aria-label="Next page"
          disabled={page * size >= total}
          onClick={() => onChange(page + 1)}
        >
          <ChevronRight size={17} />
        </button>
      </div>
    </div>
  );
}
function TargetsPage() {
  const [page, setPage] = useState(1),
    [statusFilter, setStatusFilter] = useState(""),
    [typeFilter, setTypeFilter] = useState(""),
    [search, setSearch] = useState(""),
    [modal, setModal] = useState(null),
    [selectedTarget, setSelectedTarget] = useState(null),
    [error, setError] = useState("");

  const queryParams = new URLSearchParams();
  queryParams.set("page", String(page));
  if (statusFilter) queryParams.set("status", statusFilter);
  if (typeFilter) queryParams.set("type", typeFilter);
  if (search) queryParams.set("search", search);

  const r = useLoad(`/api/targets?${queryParams.toString()}`);
  const targets = r.data || [];
  const metrics = r.meta?.metrics || {
    total: 0,
    active: 0,
    expired: 0,
    revoked: 0,
    inactive: 0,
  };

  return (
    <>
      <Heading
        eyebrow="AUTHORIZED SCOPE & TARGETS"
        title="Authorized targets"
        action={
          <button
            className="primary"
            onClick={() => {
              setError("");
              setModal("register");
            }}
          >
            <Plus size={18} />
            Register target
          </button>
        }
      >
        Manage registered targets, explicit scope boundaries, and documented permissions.
      </Heading>
      <ErrorBox message={r.error || error} />
      <div className="metrics dashboard-metrics">
        <article className="metric">
          <div>
            Total targets <Target size={18} />
          </div>
          <strong>{metrics.total || 0}</strong>
          <small>All registered targets</small>
        </article>
        <article className="metric">
          <div>
            Active (in scope) <CheckCircle2 size={18} />
          </div>
          <strong>{metrics.active || 0}</strong>
          <small>Authorized & unexpired</small>
        </article>
        <article className="metric">
          <div>
            Expired scope <Clock size={18} />
          </div>
          <strong>{metrics.expired || 0}</strong>
          <small>Requires scope renewal</small>
        </article>
        <article className="metric">
          <div>
            Revoked / Inactive <Ban size={18} />
          </div>
          <strong>{(metrics.revoked || 0) + (metrics.inactive || 0)}</strong>
          <small>Permission paused or revoked</small>
        </article>
      </div>

      <section className="panel">
        <div className="panel-title">
          <h2>Registered targets</h2>
          <div className="filters" style={{ padding: 0 }}>
            <select
              aria-label="Filter target status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All statuses</option>
              <option value="active">Active</option>
              <option value="expired">Expired</option>
              <option value="revoked">Revoked</option>
              <option value="inactive">Inactive</option>
              <option value="pending_approval">Pending approval</option>
            </select>
            <select
              aria-label="Filter authorization type"
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All authorization types</option>
              <option value="organization">Organization assets</option>
              <option value="client">Client assessment</option>
              <option value="bug_bounty">Bug bounty program</option>
              <option value="lab">Practice lab / CTF</option>
            </select>
            <input
              aria-label="Search targets"
              placeholder="Search name, owner, or domain…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
            />
          </div>
        </div>

        {r.loading && !targets.length ? (
          <div className="loading">Loading authorized targets…</div>
        ) : targets.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Target name / Scope</th>
                  <th>Type & Organization</th>
                  <th>Validity & Expiry</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <button
                        className="finding-link"
                        onClick={() => {
                          setSelectedTarget(t);
                          setModal("details");
                        }}
                      >
                        <strong>{t.name}</strong>
                        <small>
                          {(t.scope_domains || []).slice(0, 3).join(", ")}
                          {(t.scope_domains || []).length > 3
                            ? ` +${t.scope_domains.length - 3} more`
                            : ""}
                        </small>
                      </button>
                    </td>
                    <td>
                      <span className="capitalize">{pretty(t.target_type)}</span>
                      <small style={{ display: "block", color: "var(--ui-muted)" }}>
                        {t.owner_organization}
                      </small>
                    </td>
                    <td>
                      <span style={{ fontSize: "11px" }}>
                        Valid to: {date(t.valid_to)}
                      </span>
                    </td>
                    <td>
                      <Badge value={t.effective_status} />
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          className="secondary"
                          style={{ minHeight: "30px", padding: "4px 8px", fontSize: "11px" }}
                          onClick={() => {
                            setSelectedTarget(t);
                            setModal("details");
                          }}
                        >
                          Details
                        </button>
                        {t.effective_status !== "revoked" && (
                          <button
                            className="secondary danger"
                            style={{ minHeight: "30px", padding: "4px 8px", fontSize: "11px" }}
                            onClick={() => {
                              setSelectedTarget(t);
                              setModal("deactivate");
                            }}
                          >
                            Deactivate
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No registered authorized targets">
            Register targets with documented authorization before assessing them. Scope boundaries and expiry will be tracked here.
          </Empty>
        )}
        <Pagination page={page} total={r.meta?.total || 0} onChange={setPage} />
      </section>

      {modal === "register" && (
        <RegisterTargetModal
          onClose={() => setModal(null)}
          onSuccess={() => {
            setModal(null);
            r.reload();
          }}
        />
      )}

      {modal === "details" && selectedTarget && (
        <TargetDetailsModal
          targetId={selectedTarget.id}
          onClose={() => {
            setModal(null);
            setSelectedTarget(null);
          }}
          onRefresh={() => {
            r.reload();
          }}
        />
      )}

      {modal === "deactivate" && selectedTarget && (
        <DeactivateTargetModal
          target={selectedTarget}
          onClose={() => {
            setModal(null);
            setSelectedTarget(null);
          }}
          onSuccess={() => {
            setModal(null);
            setSelectedTarget(null);
            r.reload();
          }}
        />
      )}
    </>
  );
}

function RegisterTargetModal({ onClose, onSuccess }) {
  const [name, setName] = useState("");
  const [targetType, setTargetType] = useState("organization");
  const [ownerOrganization, setOwnerOrganization] = useState("");
  const [scopeDomains, setScopeDomains] = useState("");
  const [explicitSubdomains, setExplicitSubdomains] = useState("");
  const [excludedScope, setExcludedScope] = useState("");
  const nowStr = new Date().toISOString().slice(0, 16);
  const futureStr = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 16);
  const [validFrom, setValidFrom] = useState(nowStr);
  const [validTo, setValidTo] = useState(futureStr);
  const [rateLimitRps, setRateLimitRps] = useState(10);
  const [permittedMethods, setPermittedMethods] = useState([
    "port_scan",
    "web_service_discovery",
    "tls_audit",
    "vulnerability_check",
  ]);
  const [prohibitedMethods, setProhibitedMethods] = useState([
    "dos",
    "exploit",
    "credential_attack",
    "active_crawl",
  ]);
  const [evidenceReference, setEvidenceReference] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showSubdomains, setShowSubdomains] = useState(false);
  const [showExclusions, setShowExclusions] = useState(false);

  const methodOptions = [
    ["port_scan", "Port scan"],
    ["web_service_discovery", "Web service discovery"],
    ["tls_audit", "TLS / SSL audit"],
    ["vulnerability_check", "Vulnerability verification"],
    ["active_crawl", "Active web crawl"],
  ];

  const prohibitedOptions = [
    ["dos", "Denial of service"],
    ["exploit", "Exploit execution"],
    ["credential_attack", "Credential attacks"],
    ["active_crawl", "Active crawl"],
    ["local_scan", "Local filesystem scan"],
  ];

  async function submit(e) {
    e.preventDefault();
    if (!name.trim()) { setError("Target name is required."); return; }
    if (!ownerOrganization.trim()) { setError("Owner or organization name is required."); return; }
    const domains = scopeDomains.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (!domains.length) { setError("At least one in-scope domain or IP address is required."); return; }
    for (const d of domains) {
      if (d.includes("://") || (d.includes(":") && !d.startsWith("["))) {
        setError(`Scope entry '${d}' is a URL or endpoint. Scope entries must be bare hostnames, IP addresses, or canonical CIDR networks (e.g. 127.0.0.1 or 127.0.0.1/32). URLs and ports are specified when launching assessments.`);
        return;
      }
    }
    const subdomains = explicitSubdomains.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    const exclusions = excludedScope.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (!validFrom || !validTo) { setError("Valid-from and Valid-to expiry dates are required."); return; }
    if (new Date(validTo) <= new Date(validFrom)) {
      setError("Authorization expiry date (valid_to) must be after the valid_from date."); return;
    }
    if (!evidenceReference.trim()) {
      setError("Documented authorization evidence reference is required."); return;
    }
    setBusy(true); setError("");
    try {
      await api.post("/api/targets", {
        name: name.trim(),
        target_type: targetType,
        owner_organization: ownerOrganization.trim(),
        scope_domains: domains,
        explicit_subdomains: subdomains,
        excluded_scope: exclusions,
        valid_from: new Date(validFrom).toISOString(),
        valid_to: new Date(validTo).toISOString(),
        rate_limit_rps: Number(rateLimitRps) || 10,
        permitted_methods: permittedMethods,
        prohibited_methods: prohibitedMethods,
        evidence_reference: evidenceReference.trim(),
      });
      onSuccess();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function togglePermitted(method) {
    setPermittedMethods((prev) => {
      const exists = prev.includes(method);
      if (exists) {
        return prev.filter((m) => m !== method);
      } else {
        setProhibitedMethods((prohib) => prohib.filter((m) => m !== method));
        return [...prev, method];
      }
    });
  }

  function toggleProhibited(method) {
    setProhibitedMethods((prev) => {
      const exists = prev.includes(method);
      if (exists) {
        return prev.filter((m) => m !== method);
      } else {
        setPermittedMethods((perm) => perm.filter((m) => m !== method));
        return [...prev, method];
      }
    });
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="modal target-modal tm-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Register authorized target"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Sticky header */}
        <div className="tm-header">
          <div>
            <span className="eyebrow">TARGET REGISTRATION</span>
            <h2>Register Authorized Target</h2>
          </div>
          <button className="modal-close tm-close-btn" aria-label="Close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={submit} className="tm-form">
          <div className="tm-form-body">
            {/* Section 1: Identity */}
          <div className="tm-section">
            <div className="tm-section-label">
              <span className="tm-section-num">1</span>
              <span>Target Identity</span>
            </div>
            <div className="form-grid-2">
              <div>
                <label htmlFor="target-name">Target friendly name</label>
                <input
                  id="target-name"
                  required
                  placeholder="e.g. Primary Web Portal"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="target-type">Authorization type</label>
                <select
                  id="target-type"
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value)}
                >
                  <option value="organization">Organization-owned assets</option>
                  <option value="client">Client-authorized assessment</option>
                  <option value="bug_bounty">Bug bounty program</option>
                  <option value="lab">Practice lab / CTF</option>
                </select>
              </div>
            </div>
            <div style={{ marginTop: "12px" }}>
              <label htmlFor="owner-org">Target owner or organization</label>
              <input
                id="owner-org"
                required
                placeholder="e.g. ACME Technologies Ltd."
                value={ownerOrganization}
                onChange={(e) => setOwnerOrganization(e.target.value)}
              />
            </div>
          </div>

          {/* Section 2: Scope Specification */}
          <div className="tm-section">
            <div className="tm-section-label">
              <span className="tm-section-num">2</span>
              <span>Scope Specification</span>
            </div>

            <label htmlFor="scope-domains">
              In-scope domains and IP addresses
            </label>
            <textarea
              id="scope-domains"
              rows={3}
              required
              placeholder={"One per line or comma-separated\ne.g. example.com, 127.0.0.1"}
              value={scopeDomains}
              onChange={(e) => setScopeDomains(e.target.value)}
            />
            <div className="tm-scope-notice">
              <ShieldCheck size={13} />
              Exact hosts and canonical CIDR networks only. URLs and ports are specified when launching assessments.
            </div>

            <button
              type="button"
              className="tm-collapsible-toggle"
              onClick={() => setShowSubdomains((v) => !v)}
              aria-expanded={showSubdomains}
            >
              <ChevronRight size={14} className={showSubdomains ? "tm-chevron-open" : ""} />
              Explicitly authorized subdomains
              <span className="tm-optional-tag">optional</span>
            </button>
            {showSubdomains && (
              <div className="tm-collapsible-body">
                <textarea
                  id="explicit-subdomains"
                  rows={2}
                  placeholder="api.example.com, auth.example.com"
                  value={explicitSubdomains}
                  onChange={(e) => setExplicitSubdomains(e.target.value)}
                />
              </div>
            )}

            <button
              type="button"
              className="tm-collapsible-toggle"
              onClick={() => setShowExclusions((v) => !v)}
              aria-expanded={showExclusions}
            >
              <ChevronRight size={14} className={showExclusions ? "tm-chevron-open" : ""} />
              Excluded hosts, paths, or IPs
              <span className="tm-optional-tag">optional</span>
            </button>
            {showExclusions && (
              <div className="tm-collapsible-body">
                <textarea
                  id="excluded-scope"
                  rows={2}
                  placeholder="/admin/billing, test.example.com, 192.168.1.99"
                  value={excludedScope}
                  onChange={(e) => setExcludedScope(e.target.value)}
                />
                <small className="tm-hint">
                  Excluded paths use strict boundary matching — /admin matches /admin/ and /admin/billing, but not /administrator.
                </small>
              </div>
            )}
          </div>

          {/* Section 3: Time Window & Rate Limits */}
          <div className="tm-section">
            <div className="tm-section-label">
              <span className="tm-section-num">3</span>
              <span>Time Window &amp; Rate Limits</span>
            </div>
            <div className="tm-time-rate-grid">
              <div>
                <label htmlFor="valid-from">
                  <Calendar size={12} /> Valid from
                </label>
                <input
                  id="valid-from"
                  type="datetime-local"
                  required
                  value={validFrom}
                  onChange={(e) => setValidFrom(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="valid-to">
                  <Calendar size={12} /> Expiry (valid to)
                </label>
                <input
                  id="valid-to"
                  type="datetime-local"
                  required
                  value={validTo}
                  onChange={(e) => setValidTo(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="rate-limit">
                  <Activity size={12} /> Max rate (req/s)
                </label>
                <input
                  id="rate-limit"
                  type="number"
                  min={1}
                  max={1000}
                  value={rateLimitRps}
                  onChange={(e) => setRateLimitRps(e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* Section 4: Assessment Methods */}
          <div className="tm-section">
            <div className="tm-section-label">
              <span className="tm-section-num">4</span>
              <span>Assessment Methods</span>
            </div>

            <label className="tm-sub-label">Permitted methods</label>
            <div className="chip-list">
              {methodOptions.map(([val, label]) => (
                <label key={val} className={`chip tm-permitted-chip${permittedMethods.includes(val) ? " active" : ""}`} style={{ cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={permittedMethods.includes(val)}
                    onChange={() => togglePermitted(val)}
                  />
                  {permittedMethods.includes(val) && <CheckCircle2 size={11} />}
                  <span>{label}</span>
                </label>
              ))}
            </div>

            <label className="tm-sub-label" style={{ marginTop: "12px" }}>
              Prohibited methods
              <span className="tm-hint-inline"> — always enforced by backend policy</span>
            </label>
            <div className="chip-list">
              {prohibitedOptions.map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  className={`tm-restriction-tag${prohibitedMethods.includes(val) ? " active" : ""}`}
                  onClick={() => toggleProhibited(val)}
                  aria-pressed={prohibitedMethods.includes(val)}
                >
                  <Ban size={11} />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Section 5: Evidence & Compliance */}
          <div className="tm-section">
            <div className="tm-section-label">
              <span className="tm-section-num">5</span>
              <span>Evidence &amp; Compliance</span>
            </div>
            <label htmlFor="evidence-ref">Documented authorization evidence reference</label>
            <textarea
              id="evidence-ref"
              rows={2}
              required
              placeholder="e.g. SOW REF-2026-0819, Signed Letter from CISO, or Official Bug Bounty Policy URL"
              value={evidenceReference}
              onChange={(e) => setEvidenceReference(e.target.value)}
            />
            <div className="tm-compliance-warning">
              <AlertTriangle size={13} />
              Do not paste passwords, API keys, tokens, or raw confidential files. Provide only a reference or identifier.
            </div>
          </div>

          <ErrorBox message={error} />
          </div>

          {/* Modal footer */}
          <div className="tm-footer">
            <button type="button" className="secondary" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="primary tm-submit-btn" disabled={busy}>
              {busy ? (
                <><RefreshCw size={14} className="spin" /> Registering&hellip;</>
              ) : (
                <><ShieldCheck size={14} /> Register authorized target</>
              )}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function ScopeImportReview({ snapshot, busy, onDecide, compact = false }) {
  if (!snapshot) return null;
  const validatedAt = snapshot.last_successful_validation_at
    ? new Date(snapshot.last_successful_validation_at)
    : null;
  const stale = !validatedAt || Date.now() - validatedAt.getTime() > 30 * 24 * 60 * 60 * 1000;
  const diff = snapshot.scope_diff || {};
  const assets = (items) => (items || []).map((item) => `${item.value} (${item.asset_type})`).join(", ") || "None";
  return (
    <div className="panel" style={{ marginTop: "10px", padding: compact ? "10px" : "14px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", flexWrap: "wrap" }}>
        <strong>{snapshot.provider} / {snapshot.program_id} · {snapshot.snapshot_version}</strong>
        <span>
          <Badge value={snapshot.import_status} /> <Badge value={snapshot.approval_status} />
          {stale && <Badge value="stale" />}
        </span>
      </div>
      <p className="muted">Source reference: {snapshot.source_url}</p>
      <p className="muted">Imported: {date(snapshot.imported_at)} · Last validated: {date(snapshot.last_successful_validation_at)}</p>
      <p className="muted">Digest: {snapshot.digest}</p>
      <div>
        <strong>Included:</strong> {assets(snapshot.included_assets)}
        <br /><strong>Excluded:</strong> {assets(snapshot.excluded_assets)}
        <br /><strong>Permitted:</strong> {(snapshot.permitted_methods || []).join(", ") || "None"}
        <br /><strong>Prohibited:</strong> {(snapshot.prohibited_methods || []).join(", ") || "None"}
        <br /><strong>Program restrictions:</strong> {(snapshot.restrictions || []).join("; ") || "None"}
      </div>
      <div style={{ marginTop: "8px" }}>
        <strong>Scope diff requiring review</strong>
        <p>Newly included: {assets(diff.newly_included)}</p>
        <p>Removed: {assets(diff.removed)}</p>
        <p>Exclusions added: {assets(diff.exclusions_added)} · removed: {assets(diff.exclusions_removed)}</p>
        <p>Methods changed: {diff.methods_changed ? "Yes" : "No"}</p>
      </div>
      {(snapshot.invalid_entries || []).length > 0 && (
        <div role="alert">
          <strong>Invalid entries</strong>
          <ul>{snapshot.invalid_entries.map((entry, index) => (
            <li key={`${entry.index}-${index}`}>{entry.index}: {entry.error}</li>
          ))}</ul>
        </div>
      )}
      {!compact && snapshot.approval_status === "pending_review" && snapshot.import_status === "valid" && !stale && (
        <div style={{ display: "flex", gap: "8px", marginTop: "10px" }}>
          <button className="primary" disabled={busy} onClick={() => onDecide(snapshot.id, "approve")}>Approve imported scope</button>
          <button className="secondary danger" disabled={busy} onClick={() => onDecide(snapshot.id, "reject")}>Reject import</button>
        </div>
      )}
    </div>
  );
}

function TargetDetailsModal({ targetId, onClose, onRefresh, startEditing = false }) {
  const r = useLoad("/api/targets/" + targetId);
  const importsResp = useLoad("/api/targets/" + targetId + "/scope-imports");
  const target = r.data;
  const importHistory = Array.isArray(importsResp.data?.data)
    ? importsResp.data.data
    : Array.isArray(importsResp.data)
      ? importsResp.data
      : [];
  const [editing, setEditing] = useState(Boolean(startEditing));
  const [importing, setImporting] = useState(false);
  const [provider, setProvider] = useState("");
  const [programId, setProgramId] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [fixture, setFixture] = useState('{\n  "version": "offline-fixture-v1",\n  "assets": [\n    { "asset_type": "domain", "value": "example.test", "scope": "included" }\n  ],\n  "permitted_methods": ["web_service_discovery"],\n  "prohibited_methods": ["dos", "exploit"],\n  "restrictions": []\n}');
  const [scopePreview, setScopePreview] = useState(null);
  const [name, setName] = useState("");
  const [rateLimitRps, setRateLimitRps] = useState(10);
  const [validTo, setValidTo] = useState("");
  const [evidenceReference, setEvidenceReference] = useState("");
  const [permittedMethods, setPermittedMethods] = useState([]);
  const [prohibitedMethods, setProhibitedMethods] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (target) {
      setName(target.name || "");
      setRateLimitRps(target.rate_limit_rps || 10);
      setValidTo(target.valid_to ? target.valid_to.slice(0, 16) : "");
      setEvidenceReference(target.evidence_reference || "");
      setPermittedMethods(target.permitted_methods || []);
      setProhibitedMethods(target.prohibited_methods || []);
    }
  }, [target]);

  function togglePermitted(method) {
    setPermittedMethods((prev) =>
      prev.includes(method) ? prev.filter((m) => m !== method) : [...prev, method]
    );
    setProhibitedMethods((prev) => prev.filter((m) => m !== method));
  }

  function toggleProhibited(method) {
    setProhibitedMethods((prev) =>
      prev.includes(method) ? prev.filter((m) => m !== method) : [...prev, method]
    );
    setPermittedMethods((prev) => prev.filter((m) => m !== method));
  }

  async function saveEdit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.put("/api/targets/" + targetId, {
        name: name.trim(),
        rate_limit_rps: Number(rateLimitRps) || 10,
        valid_to: new Date(validTo).toISOString(),
        evidence_reference: evidenceReference.trim(),
        permitted_methods: permittedMethods,
        prohibited_methods: prohibitedMethods,
      });
      setEditing(false);
      r.reload();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function previewImport(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await api.post(`/api/targets/${targetId}/scope-imports/preview`, {
        provider: provider.trim(),
        program_id: programId.trim(),
        source_url: sourceUrl.trim(),
        fixture: JSON.parse(fixture),
      });
      setScopePreview(response.data.data);
      importsResp.reload();
    } catch (err) {
      setError(err instanceof SyntaxError ? "Scope fixture must be valid JSON." : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function decideImport(snapshotId, decision) {
    setBusy(true);
    setError("");
    try {
      const response = await api.post(
        `/api/targets/${targetId}/scope-imports/${snapshotId}/${decision}`,
        {},
      );
      setScopePreview(response.data.data.snapshot || response.data.data);
      importsResp.reload();
      r.reload();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="modal target-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Target Details"
        onClick={(e) => e.stopPropagation()}
      >
        <button className="modal-close" aria-label="Close" onClick={onClose}>
          <X />
        </button>

        {r.loading && !target ? (
          <div className="loading">Loading target details…</div>
        ) : target ? (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px" }}>
              <div>
                <span className="eyebrow">{pretty(target.target_type)}</span>
                <h2>{target.name}</h2>
                <p>Owner: <strong>{target.owner_organization}</strong></p>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <Badge value={target.effective_status} />
                <button
                  type="button"
                  className="secondary"
                  style={{ minHeight: "32px", padding: "4px 10px", fontSize: "11px" }}
                  onClick={() => setEditing((v) => !v)}
                >
                  <Edit2 size={13} style={{ marginRight: "4px", verticalAlign: "middle" }} />
                  {editing ? "Cancel edit" : "Edit target & permissions"}
                </button>
              </div>
            </div>

            {editing ? (
              <form onSubmit={saveEdit} style={{ marginTop: "20px" }}>
                <div className="form-grid-2">
                  <div>
                    <label htmlFor="edit-name">Target name</label>
                    <input
                      id="edit-name"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                  <div>
                    <label htmlFor="edit-rate">Rate limit (RPS)</label>
                    <input
                      id="edit-rate"
                      type="number"
                      min={1}
                      max={1000}
                      value={rateLimitRps}
                      onChange={(e) => setRateLimitRps(e.target.value)}
                    />
                  </div>
                </div>
                <div style={{ marginTop: "12px" }}>
                  <label htmlFor="edit-valid-to">Authorization expiry (valid to)</label>
                  <input
                    id="edit-valid-to"
                    type="datetime-local"
                    required
                    value={validTo}
                    onChange={(e) => setValidTo(e.target.value)}
                  />
                </div>
                <div style={{ marginTop: "12px" }}>
                  <label htmlFor="edit-evidence">Authorization evidence reference</label>
                  <textarea
                    id="edit-evidence"
                    rows={2}
                    required
                    placeholder="Documented contract, letter ID, or authorization ticket reference"
                    value={evidenceReference}
                    onChange={(e) => setEvidenceReference(e.target.value)}
                  />
                </div>

                <div className="methods-edit-section" style={{ marginTop: "16px" }}>
                  <label style={{ fontWeight: "600", fontSize: "13px", display: "block", marginBottom: "4px" }}>
                    Permitted assessment methods
                  </label>
                  <p className="muted" style={{ fontSize: "11px", marginBottom: "8px" }}>
                    Explicitly authorized scanner actions for this target.
                  </p>
                  <div className="methods-checkbox-grid">
                    {TARGET_METHOD_OPTIONS.map(([val, label]) => {
                      const isPermitted = permittedMethods.includes(val);
                      return (
                        <label key={val} className={`method-checkbox-item ${isPermitted ? "checked" : ""}`}>
                          <input
                            type="checkbox"
                            checked={isPermitted}
                            onChange={() => togglePermitted(val)}
                          />
                          <span>{label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div className="methods-edit-section" style={{ marginTop: "16px" }}>
                  <label style={{ fontWeight: "600", fontSize: "13px", display: "block", marginBottom: "4px" }}>
                    Prohibited assessment methods
                  </label>
                  <p className="muted" style={{ fontSize: "11px", marginBottom: "8px" }}>
                    Methods explicitly forbidden by target policy or scope agreement.
                  </p>
                  <div className="methods-checkbox-grid">
                    {TARGET_PROHIBITED_OPTIONS.map(([val, label]) => {
                      const isProhibited = prohibitedMethods.includes(val);
                      return (
                        <label key={val} className={`method-checkbox-item prohibited ${isProhibited ? "checked" : ""}`}>
                          <input
                            type="checkbox"
                            checked={isProhibited}
                            onChange={() => toggleProhibited(val)}
                          />
                          <span>{label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <ErrorBox message={error} />
                <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end", marginTop: "18px" }}>
                  <button type="button" className="secondary" onClick={() => setEditing(false)} disabled={busy}>
                    Cancel
                  </button>
                  <button type="submit" className="primary" disabled={busy}>
                    {busy ? "Saving…" : "Save changes"}
                  </button>
                </div>
              </form>
            ) : (
              <div style={{ marginTop: "20px" }}>
                <div className="form-grid-2">
                  <div>
                    <strong>Valid from:</strong> {date(target.valid_from)}
                  </div>
                  <div>
                    <strong>Valid until:</strong> {date(target.valid_to)}
                  </div>
                </div>

                <div style={{ marginTop: "16px" }}>
                  <strong>In-scope authorized domains / IPs:</strong>
                  <div className="chip-list">
                    {(target.scope_domains || []).map((d) => (
                      <span className="chip" key={d}>
                        <Globe size={12} /> {d}
                      </span>
                    ))}
                  </div>
                </div>

                {(target.explicit_subdomains || []).length > 0 && (
                  <div style={{ marginTop: "14px" }}>
                    <strong>Explicitly authorized subdomains:</strong>
                    <div className="chip-list">
                      {target.explicit_subdomains.map((s) => (
                        <span className="chip" key={s}>
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {(target.excluded_scope || []).length > 0 && (
                  <div style={{ marginTop: "14px" }}>
                    <strong>Explicitly excluded scope:</strong>
                    <div className="chip-list">
                      {target.excluded_scope.map((ex) => (
                        <span className="chip prohibited" key={ex}>
                          <Ban size={12} /> {ex}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ marginTop: "16px" }}>
                  <strong>Permitted methods:</strong>{" "}
                  {(target.permitted_methods || []).join(", ") || "No method restriction recorded"}
                  <br />
                  <strong>Prohibited methods:</strong>{" "}
                  {(target.prohibited_methods || []).join(", ") || "None recorded"}
                </div>

                <div style={{ marginTop: "16px" }}>
                  <strong>Documented evidence reference:</strong>
                  <p style={{ marginTop: "4px", background: "var(--ui-surface-alt)", padding: "10px", borderRadius: "6px" }}>
                    {target.evidence_reference}
                  </p>
                </div>

                <div style={{ marginTop: "16px" }}>
                  <strong>Audit information:</strong>
                  <p style={{ fontSize: "11px", color: "var(--ui-muted)" }}>
                    Created by <strong>{target.created_by}</strong> on {date(target.created_at)}
                    {target.updated_by && ` · Updated by ${target.updated_by} on ${date(target.updated_at)}`}
                  </p>
                </div>

                <div style={{ marginTop: "18px" }}>
                  <strong>Audit history ({target.audit_events?.length || 0} events):</strong>
                  <div className="audit-events">
                    {(target.audit_events || []).map((ev) => (
                      <div className="audit-item" key={ev.id}>
                        <div className="audit-header">
                          <span className="capitalize">{pretty(ev.event_type)}</span>
                          <span style={{ fontSize: "10px", color: "var(--ui-muted)" }}>{date(ev.created_at)}</span>
                        </div>
                        <div>
                          By: <em>{ev.actor}</em>
                          {ev.details && (
                            <pre style={{ fontSize: "10px", margin: "4px 0 0", padding: "4px", background: "var(--ui-surface)", overflowX: "auto" }}>
                              {JSON.stringify(ev.details, null, 2)}
                            </pre>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {target.target_type === "bug_bounty" && (
                  <section className="panel" style={{ marginTop: "18px", padding: "14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", alignItems: "center" }}>
                      <div>
                        <strong>Offline bug bounty scope imports</strong>
                        <p className="muted">No external program is contacted. Imported scope remains pending until explicitly approved.</p>
                      </div>
                      <button className="secondary" type="button" onClick={() => { setImporting((v) => !v); setError(""); }}>
                        {importing ? "Close import" : "Import offline JSON"}
                      </button>
                    </div>
                    {importing && (
                      <form onSubmit={previewImport} style={{ marginTop: "12px" }}>
                        <div className="form-grid-2">
                          <div>
                            <label htmlFor="scope-provider">Provider name</label>
                            <input id="scope-provider" required value={provider} onChange={(e) => setProvider(e.target.value)} />
                          </div>
                          <div>
                            <label htmlFor="scope-program-id">Program identifier</label>
                            <input id="scope-program-id" required value={programId} onChange={(e) => setProgramId(e.target.value)} />
                          </div>
                        </div>
                        <label htmlFor="scope-source-url">Source URL (reference only)</label>
                        <input id="scope-source-url" type="url" required value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} />
                        <label htmlFor="scope-fixture">Provider-neutral scope fixture JSON</label>
                        <textarea id="scope-fixture" rows={8} required value={fixture} onChange={(e) => setFixture(e.target.value)} />
                        <button className="primary" type="submit" disabled={busy}>{busy ? "Parsing…" : "Preview scope changes"}</button>
                      </form>
                    )}
                    {scopePreview && (
                      <ScopeImportReview
                        snapshot={scopePreview}
                        busy={busy}
                        onDecide={decideImport}
                      />
                    )}
                    <ErrorBox message={error} />
                    <div style={{ marginTop: "12px" }}>
                      <strong>Import history ({importHistory.length})</strong>
                      {importsResp.loading && <p className="muted" style={{ fontSize: "11px", margin: "6px 0 0" }}>Loading import history…</p>}
                      {!importsResp.loading && !importsResp.error && importHistory.length === 0 && (
                        <p className="muted" style={{ fontSize: "11px", margin: "6px 0 0" }}>No scope import history recorded.</p>
                      )}
                      {importHistory.map((item) => (
                        <ScopeImportReview key={item.id} snapshot={item} busy={busy} onDecide={decideImport} compact />
                      ))}
                      {importsResp.error && <ErrorBox message={importsResp.error} />}
                    </div>
                  </section>
                )}
              </div>
            )}
          </>
        ) : (
          <ErrorBox message={r.error || "Target not found"} />
        )}
      </section>
    </div>
  );
}

function DeactivateTargetModal({ target, onClose, onSuccess }) {
  const [status, setStatus] = useState("inactive");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.post(`/api/targets/${target.id}/deactivate`, {
        status,
        reason: reason.trim() || "Deactivated by administrator.",
      });
      onSuccess();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Deactivate target"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: "520px" }}
      >
        <button className="modal-close" aria-label="Close" onClick={onClose}>
          <X />
        </button>
        <span className="eyebrow">CHANGE AUTHORIZATION STATUS</span>
        <h2>Deactivate Target Scope</h2>
        <p>
          Target: <strong>{target.name}</strong> ({target.owner_organization})
        </p>

        <form onSubmit={submit} style={{ marginTop: "18px" }}>
          <div>
            <label htmlFor="deact-status">New status</label>
            <select
              id="deact-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="inactive">Temporarily Inactive (Pause assessment permission)</option>
              <option value="revoked">Revoked (Formal revocation of permission)</option>
            </select>
          </div>

          <div style={{ marginTop: "12px" }}>
            <label htmlFor="deact-reason">Reason for deactivation or revocation</label>
            <textarea
              id="deact-reason"
              rows={2}
              required
              placeholder="e.g. Scope expired, client requested testing halt, or program policy change"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          <ErrorBox message={error} />

          <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end", marginTop: "20px" }}>
            <button type="button" className="secondary" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="secondary danger" disabled={busy}>
              {busy ? "Processing…" : status === "revoked" ? "Revoke authorization" : "Deactivate target"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function HistoryPage() {
  const [page, setPage] = useState(1),
    [state, setState] = useState(""),
    [first, setFirst] = useState(""),
    [second, setSecond] = useState(""),
    [comparison, setComparison] = useState(null),
    [error, setError] = useState("");
  const r = useLoad(`/api/scans?page=${page}&state=${state}`);
  async function compare() {
    try {
      setComparison(
        (await api.get("/api/scans/compare", { params: { first, second } }))
          .data.data,
      );
      setError("");
    } catch (e) {
      setError(errorMessage(e));
    }
  }
  return (
    <>
      <Heading eyebrow="SAVED ASSESSMENTS" title="Scan history">
        Revisit evidence and compare assessments of the same target.
      </Heading>
      <ErrorBox message={r.error || error} />
      <section className="panel">
        <div className="panel-title">
          <h2>All assessments</h2>
          <select
            aria-label="Filter scan status"
            value={state}
            onChange={(e) => {
              setState(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All statuses</option>
            {["queued", "running", ...terminal].map((s) => (
              <option key={s} value={s}>
                {pretty(s)}
              </option>
            ))}
          </select>
        </div>
        {r.loading ? (
          <div className="loading">Loading history…</div>
        ) : r.data?.length ? (
          <ScanTable scans={r.data} />
        ) : (
          <Empty title="No matching scans">
            Your saved assessments will appear here.
          </Empty>
        )}
        <Pagination page={page} total={r.meta?.total || 0} onChange={setPage} />
      </section>
      <section className="panel compare">
        <h2>Compare two assessments</h2>
        <p>Missing findings are candidates for review, not confirmed fixes.</p>
        <div className="compare-controls">
          {[
            [first, setFirst, "First scan"],
            [second, setSecond, "Second scan"],
          ].map(([v, setter, label]) => (
            <select
              aria-label={label}
              key={label}
              value={v}
              onChange={(e) => setter(e.target.value)}
            >
              <option value="">{label}</option>
              {r.data
                ?.filter((s) => terminal.includes(s.state))
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} · {s.id.slice(0, 8)}
                  </option>
                ))}
            </select>
          ))}
          <button
            className="secondary"
            disabled={!first || !second}
            onClick={compare}
          >
            Compare
            <ArrowRight size={15} />
          </button>
        </div>
        {comparison && (
          <>
            <div className="note">{comparison.warning}</div>
            {["new", "resolved_candidates", "unchanged"].map((k) => (
              <div key={k}>
                <h3 className="capitalize">
                  {pretty(k)} ({comparison[k].length})
                </h3>
                {comparison[k].map((f) => (
                  <p key={f.fingerprint}>
                    <Badge value={f.severity} /> {f.title}
                  </p>
                ))}
              </div>
            ))}
          </>
        )}
      </section>
    </>
  );
}

function AuditPage() {
  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);

  const queryParams = new URLSearchParams();
  queryParams.set("page", String(page));
  if (eventType) queryParams.set("event_type", eventType);
  if (actorFilter) queryParams.set("actor", actorFilter.trim());

  const r = useLoad(`/api/audit-events?${queryParams.toString()}`);
  const events = r.data || [];

  const eventTypes = [
    "scan_dispatched",
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "scan_deleted",
    "target_created",
    "target_updated",
    "target_inactive",
    "target_revoked",
    "auth_login_success",
    "auth_login_failed",
    "auth_logout",
    "auth_signup",
    "auth_register_rejected",
    "auth_rate_limited",
    "report_downloaded",
    "evidence_downloaded",
  ];

  return (
    <>
      <Heading
        eyebrow="COMPLIANCE & TRACEABILITY"
        title="Audit trail"
      >
        Append-only security audit log of scans, authorizations, and system operations.
      </Heading>
      <ErrorBox message={r.error} />
      <section className="panel">
        <div className="panel-title">
          <h2>Recorded events</h2>
          <div className="filters" style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            <select
              aria-label="Filter event type"
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All event types</option>
              {eventTypes.map((et) => (
                <option key={et} value={et}>
                  {pretty(et)}
                </option>
              ))}
            </select>
            <input
              aria-label="Filter actor"
              placeholder="Filter by actor"
              value={actorFilter}
              onChange={(e) => {
                setActorFilter(e.target.value);
                setPage(1);
              }}
              style={{ minWidth: "160px" }}
            />
          </div>
        </div>

        {r.loading ? (
          <div className="loading">Loading audit records…</div>
        ) : events.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Actor</th>
                  <th>Resource</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td className="muted nowrap">{date(ev.created_at)}</td>
                    <td>
                      <Badge value={ev.event_type} />
                    </td>
                    <td>
                      <strong>{ev.actor}</strong>
                    </td>
                    <td className="muted">
                      {ev.resource_type ? (
                        <span>
                          {ev.resource_type}
                          {ev.resource_id && <small style={{ display: "block", color: "var(--ui-muted)" }}>{ev.resource_id.slice(0, 16)}</small>}
                        </span>
                      ) : (
                        <span className="subtle">—</span>
                      )}
                    </td>
                    <td className="muted">{ev.ip_address || "—"}</td>
                    <td>
                      <button
                        type="button"
                        className="text-link"
                        style={{ fontSize: "12px", cursor: "pointer" }}
                        onClick={() => setSelectedEvent(ev)}
                      >
                        Inspect details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No audit events found">
            No audit log records match the current filter criteria.
          </Empty>
        )}
        <Pagination page={page} total={r.meta?.total || 0} onChange={setPage} />

        {selectedEvent && (
          <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
            <section
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Audit event details"
              onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: "600px" }}
            >
              <button
                className="modal-close"
                aria-label="Close details"
                onClick={() => setSelectedEvent(null)}
              >
                <X />
              </button>
              <span className="eyebrow">AUDIT RECORD</span>
              <h2>{pretty(selectedEvent.event_type)}</h2>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", margin: "14px 0", fontSize: "13px" }}>
                <div><strong>Event ID:</strong> <span style={{ wordBreak: "break-all" }}>{selectedEvent.id}</span></div>
                <div><strong>Timestamp:</strong> {date(selectedEvent.created_at)}</div>
                <div><strong>Actor:</strong> {selectedEvent.actor}</div>
                <div><strong>IP Address:</strong> {selectedEvent.ip_address || "None"}</div>
                {selectedEvent.resource_type && (
                  <div><strong>Resource:</strong> {selectedEvent.resource_type} ({selectedEvent.resource_id || "N/A"})</div>
                )}
              </div>
              <h3>Redacted payload details</h3>
              <pre style={{ background: "var(--ui-surface)", padding: "10px", borderRadius: "6px", overflowX: "auto", fontSize: "12px" }}>
                {JSON.stringify(selectedEvent.details, null, 2)}
              </pre>
            </section>
          </div>
        )}
      </section>
    </>
  );
}

function EvidencePage() {
  const [page, setPage] = useState(1);
  const [toolFilter, setToolFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [scanFilter, setScanFilter] = useState("");
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [downloadingAction, setDownloadingAction] = useState(null);
  const [error, setError] = useState("");

  const queryParams = new URLSearchParams();
  queryParams.set("page", String(page));
  if (toolFilter) queryParams.set("tool", toolFilter);
  if (typeFilter) queryParams.set("evidence_type", typeFilter);
  if (scanFilter) queryParams.set("scan_id", scanFilter.trim());

  const r = useLoad(`/api/evidence?${queryParams.toString()}`);
  const items = r.data || [];

  const tools = ["nmap", "subfinder", "httpx", "whatweb", "nuclei", "sslyze", "wapiti", "gitleaks", "trivy"];
  const evidenceTypes = ["raw_output", "report", "certificate", "screenshot", "log"];

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  async function handleDownloadRaw(ev) {
    setDownloadingAction(`${ev.id}_raw`);
    setError("");
    try {
      const filename = `${ev.tool}_${ev.evidence_type}_${ev.id.slice(0, 8)}.txt`;
      await downloadEvidence(ev.id, filename);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setDownloadingAction(null);
    }
  }

  async function handleDownloadPdf(ev) {
    setDownloadingAction(`${ev.id}_pdf`);
    setError("");
    try {
      const filename = `${ev.tool}_${ev.evidence_type}_${ev.id.slice(0, 8)}_report.pdf`;
      await downloadEvidencePdf(ev.id, filename);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setDownloadingAction(null);
    }
  }

  async function handleViewPdf(ev) {
    setDownloadingAction(`${ev.id}_view`);
    setError("");
    try {
      await previewEvidencePdf(ev.id);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setDownloadingAction(null);
    }
  }

  return (
    <>
      <Heading
        eyebrow="VERIFIABLE ARTIFACTS"
        title="Evidence locker"
      >
        Cryptographically verified tool outputs, reports, and execution artifacts.
      </Heading>
      <ErrorBox message={r.error || error} />
      <section className="panel">
        <div className="panel-title">
          <h2>Evidence records</h2>
          <div className="filters" style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            <select
              aria-label="Filter tool"
              value={toolFilter}
              onChange={(e) => {
                setToolFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All tools</option>
              {tools.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter evidence type"
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All evidence types</option>
              {evidenceTypes.map((et) => (
                <option key={et} value={et}>
                  {pretty(et)}
                </option>
              ))}
            </select>
            <input
              aria-label="Filter scan ID"
              placeholder="Filter by scan ID"
              value={scanFilter}
              onChange={(e) => {
                setScanFilter(e.target.value);
                setPage(1);
              }}
              style={{ minWidth: "160px" }}
            />
          </div>
        </div>

        {r.loading ? (
          <div className="loading">Loading evidence artifacts…</div>
        ) : items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Tool</th>
                  <th>Type</th>
                  <th>Scan ID</th>
                  <th>Size</th>
                  <th>SHA-256 Digest</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((ev) => (
                  <tr key={ev.id}>
                    <td className="muted nowrap">{date(ev.created_at)}</td>
                    <td>
                      <strong>{ev.tool}</strong>
                    </td>
                    <td>
                      <Badge value={ev.evidence_type} />
                    </td>
                    <td>
                      <a href={`#/scan/${ev.scan_id}`} className="scope-target-link">
                        {ev.scan_id.slice(0, 8)}…
                      </a>
                    </td>
                    <td className="muted nowrap">{formatBytes(ev.file_size)}</td>
                    <td>
                      <code
                        title={ev.sha256_hash}
                        style={{ cursor: "pointer", background: "var(--ui-surface)", padding: "2px 6px", borderRadius: "4px" }}
                        onClick={() => setSelectedEvidence(ev)}
                      >
                        {ev.sha256_hash.slice(0, 12)}…
                      </code>
                    </td>
                    <td className="evidence-actions-cell">
                      <div className="evidence-btn-group">
                        <button
                          type="button"
                          className="btn-evidence-action btn-evidence-view"
                          title="View PDF preview in a new tab"
                          aria-label="View PDF"
                          disabled={downloadingAction === `${ev.id}_view`}
                          onClick={() => handleViewPdf(ev)}
                        >
                          <Eye size={12} />
                          <span>{downloadingAction === `${ev.id}_view` ? "Opening…" : "View"}</span>
                        </button>
                        <button
                          type="button"
                          className="btn-evidence-action btn-evidence-pdf"
                          title="Download human-readable derived PDF report"
                          aria-label="Export PDF report"
                          disabled={downloadingAction === `${ev.id}_pdf`}
                          onClick={() => handleDownloadPdf(ev)}
                        >
                          <FileText size={12} />
                          <span>{downloadingAction === `${ev.id}_pdf` ? "Generating…" : "PDF"}</span>
                        </button>
                        <button
                          type="button"
                          className="btn-evidence-action btn-evidence-raw"
                          title="Download original raw artifact"
                          aria-label="Download raw artifact"
                          disabled={downloadingAction === `${ev.id}_raw`}
                          onClick={() => handleDownloadRaw(ev)}
                        >
                          <Download size={12} />
                          <span>{downloadingAction === `${ev.id}_raw` ? "Downloading…" : "Raw"}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No evidence artifacts">
            Evidence records are automatically stored as assessment scans execute.
          </Empty>
        )}
        <Pagination page={page} total={r.meta?.total || 0} onChange={setPage} />

        {selectedEvidence && (
          <div className="modal-backdrop" onClick={() => setSelectedEvidence(null)}>
            <section
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Evidence details"
              onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: "600px" }}
            >
              <button
                className="modal-close"
                aria-label="Close details"
                onClick={() => setSelectedEvidence(null)}
              >
                <X />
              </button>
              <span className="eyebrow">VERIFIED EVIDENCE ARTIFACT</span>
              <h2>{selectedEvidence.tool} — {pretty(selectedEvidence.evidence_type)}</h2>
              <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "10px", margin: "14px 0", fontSize: "13px" }}>
                <div><strong>Evidence ID:</strong> <code>{selectedEvidence.id}</code></div>
                <div><strong>Scan ID:</strong> <a href={`#/scan/${selectedEvidence.scan_id}`}>{selectedEvidence.scan_id}</a></div>
                <div><strong>File Path:</strong> <code>{selectedEvidence.file_path}</code></div>
                <div><strong>File Size:</strong> {formatBytes(selectedEvidence.file_size)} ({selectedEvidence.file_size} bytes)</div>
                <div>
                  <strong>Cryptographic SHA-256 Digest:</strong>
                  <pre style={{ margin: "4px 0 0", padding: "6px", background: "var(--ui-surface)", wordBreak: "break-all", fontSize: "12px" }}>
                    {selectedEvidence.sha256_hash}
                  </pre>
                </div>
                <div><strong>Derived PDF Report:</strong> Supported (Formatted and Escaped)</div>
                <div><strong>Redacted Flag:</strong> {selectedEvidence.redacted ? "Yes (Local/Passive redaction applied)" : "No"}</div>
                <div><strong>Created:</strong> {date(selectedEvidence.created_at)}</div>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "16px", flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="secondary"
                  disabled={downloadingAction === `${selectedEvidence.id}_raw`}
                  onClick={() => handleDownloadRaw(selectedEvidence)}
                >
                  <Download size={14} />
                  <span>{downloadingAction === `${selectedEvidence.id}_raw` ? "Downloading…" : "Download Raw Artifact"}</span>
                </button>
                <button
                  type="button"
                  className="secondary"
                  disabled={downloadingAction === `${selectedEvidence.id}_view`}
                  onClick={() => handleViewPdf(selectedEvidence)}
                >
                  <Eye size={14} />
                  <span>{downloadingAction === `${selectedEvidence.id}_view` ? "Opening…" : "View PDF"}</span>
                </button>
                <button
                  type="button"
                  className="primary"
                  disabled={downloadingAction === `${selectedEvidence.id}_pdf`}
                  onClick={() => handleDownloadPdf(selectedEvidence)}
                >
                  <FileText size={14} />
                  <span>{downloadingAction === `${selectedEvidence.id}_pdf` ? "Generating…" : "Download Derived PDF"}</span>
                </button>
              </div>
            </section>
          </div>
        )}
      </section>
    </>
  );
}

function ScanDetail({ id }) {
  const [terminalReached, setTerminalReached] = useState(false);
  useEffect(() => {
    setTerminalReached(false);
  }, [id]);

  const pollInterval = terminalReached ? 0 : 1200;
  const r = useLoad("/api/scans/" + id, pollInterval),
    d = r.data,
    [tab, setTab] = useState("findings"),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [confirm, setConfirm] = useState(false);

  useEffect(() => {
    if (d && terminal.includes(d.state)) {
      setTerminalReached(true);
    }
  }, [d?.state]);

  async function action(fn) {
    setBusy(true);
    try {
      await fn();
      setError("");
      r.reload();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  const finished = d && terminal.includes(d.state);
  return (
    <>
      <Heading
        eyebrow="ASSESSMENT WORKSPACE"
        title={d?.target || "Loading assessment…"}
        action={d && <Badge value={d.state} />}
      >
        Scan {id}
      </Heading>
      <ErrorBox message={r.error || error} />
      {d && (
        <>
          <section className="panel monitor">
            <div className="monitor-top">
              <div>
                <span className="eyebrow">
                  {finished ? "ASSESSMENT FINISHED" : "LIVE EXECUTION"}
                </span>
                <h2>
                  {d.progress?.current_tool
                    ? "Running " + d.progress.current_tool
                    : finished
                      ? "Review coverage and evidence"
                      : "Waiting for the worker"}
                </h2>
              </div>
              {!finished && (
                <button
                  className="secondary danger"
                  disabled={busy || d.configuration?.cancellation_requested}
                  onClick={() =>
                    action(() => api.post(`/api/scans/${id}/cancel`))
                  }
                >
                  <Square size={13} />
                  {d.configuration?.cancellation_requested
                    ? "Cancelling…"
                    : "Cancel scan"}
                </button>
              )}
            </div>
            <div className="progress-track">
              <span
                style={{
                  width: `${(100 * (d.progress?.processed || 0)) / Math.max(1, d.progress?.total || d.executions?.length || 1)}%`,
                }}
              />
            </div>
            <div className="monitor-meta">
              <span>
                {d.progress?.processed ?? 0} / {d.progress?.total ?? d.executions?.length ?? 0} stages processed
              </span>
              <span>Started {date(d.started_at)}</span>
              <Elapsed start={d.started_at} end={d.ended_at} />
            </div>
            <div className="execution-table-wrap">
              <div className="execution-list" role="table" aria-label="Tool execution stages">
                <div className="execution-header" role="row">
                  <span className="col-tool" role="columnheader">Tool stage</span>
                  <span className="col-status" role="columnheader">Status</span>
                  <span className="col-version" role="columnheader">Version</span>
                  <span className="col-details" role="columnheader">Execution details &amp; notes</span>
                </div>
                {(d.executions || []).map((t) => (
                  <div className={`execution-row ${t.state}`} key={t.id} role="row">
                    <div className="col-tool" role="cell">
                      <span className="execution-icon" aria-hidden="true">
                        {t.outcome === "COMPLETED_WITH_FINDINGS" ? (
                          <AlertTriangle size={16} />
                        ) : t.outcome === "COMPLETED_WITHOUT_FINDINGS" ? (
                          <Check size={16} />
                        ) : t.state === "completed" ? (
                          <Check size={16} />
                        ) : t.state === "running" ? (
                          <Activity size={16} className="spin" />
                        ) : t.state === "failed" ? (
                          <XCircle size={16} />
                        ) : t.state === "skipped" ? (
                          <Ban size={16} />
                        ) : (
                          <Terminal size={16} />
                        )}
                      </span>
                      <strong className="execution-tool-name">{t.tool}</strong>
                    </div>
                    <div className="col-status" role="cell">
                      <Badge value={t.outcome || t.state} />
                    </div>
                    <div className="col-version" role="cell">
                      {t.version ? (
                        <span className="execution-version" title={t.version}>{t.version}</span>
                      ) : (
                        <span className="execution-version-empty">—</span>
                      )}
                    </div>
                    <div className="col-details" role="cell">
                      {t.error && <small className="execution-detail error-or-skip">{t.error}</small>}
                      {t.limitations && <small className="execution-detail limitations">{t.limitations}</small>}
                      {!t.error && !t.limitations && t.outcome === "COMPLETED_WITH_FINDINGS" && (
                        <small className="execution-detail warning">Execution completed; potential findings recorded for review.</small>
                      )}
                      {!t.error && !t.limitations && t.outcome === "COMPLETED_WITHOUT_FINDINGS" && (
                        <small className="execution-detail neutral">Execution completed; no findings detected by this scanner.</small>
                      )}
                      {!t.error && !t.limitations && t.state === "completed" && !t.outcome?.startsWith("COMPLETED_") && (
                        <small className="execution-detail success">Execution completed; results parsed and recorded.</small>
                      )}
                      {!t.error && !t.limitations && t.state !== "completed" && (
                        <small className="execution-detail neutral">{pretty(t.outcome || t.state)}</small>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            {d.configuration?.failure && (
              <ErrorBox message={d.configuration.failure} />
            )}
          </section>
          <div className="results-heading">
            <div className="tabs">
              {["findings", "assets", "scope"].map((n) => (
                <button
                  key={n}
                  className={tab === n ? "active" : ""}
                  onClick={() => setTab(n)}
                >
                  {pretty(n)}{" "}
                  {n === "findings"
                    ? `(${d.findings?.length || 0})`
                    : n === "assets"
                      ? `(${d.assets?.length || 0})`
                      : ""}
                </button>
              ))}
            </div>
            <div className="exports">
              {finished &&
                [
                  ["pdf", "PDF report"],
                  ["html", "HTML report"],
                  ["json", "Scan JSON"],
                  ["vulnerabilities", "Findings JSON"],
                ].map(([f, label]) => (
                  <button
                    key={f}
                    className="secondary"
                    disabled={busy}
                    onClick={() => action(() => download(id, f))}
                  >
                    <Download size={14} />
                    {label}
                  </button>
                ))}
            </div>
          </div>
          {tab === "findings" ? (
            <Findings id={id} finished={finished} />
          ) : tab === "assets" ? (
            <section className="panel">
              {d.assets.length ? (
                <div className="asset-grid">
                  {d.assets.map((a) => (
                    <article key={a.id}>
                      <Badge value={a.kind} />
                      <h3>{a.address}</h3>
                      <pre>{JSON.stringify(a.details, null, 2)}</pre>
                    </article>
                  ))}
                </div>
              ) : (
                <Empty title="No assets recorded">
                  Check discovery tools for missing dependencies or failed
                  checks.
                </Empty>
              )}
            </section>
          ) : (
            <section className="panel scope-details">
              <h2>Scope and configuration</h2>
              <pre>{JSON.stringify(d.configuration, null, 2)}</pre>
              <p>
                Profile: {d.profile}. Created {date(d.created_at)}.
              </p>
            </section>
          )}
          {finished && (
            <div className="delete-area">
              {confirm ? (
                <>
                  <span>Delete this scan and its reports permanently?</span>
                  <button
                    className="secondary"
                    onClick={() => setConfirm(false)}
                  >
                    Keep scan
                  </button>
                  <button
                    className="secondary danger"
                    disabled={busy}
                    onClick={() =>
                      action(async () => {
                        await api.delete("/api/scans/" + id, {
                          headers: { "X-Confirm-Delete": id },
                        });
                        go("/history");
                      })
                    }
                  >
                    Confirm delete
                  </button>
                </>
              ) : (
                <button
                  className="text-link danger"
                  onClick={() => setConfirm(true)}
                >
                  Delete assessment
                </button>
              )}
            </div>
          )}
        </>
      )}
    </>
  );
}
function Elapsed({ start, end }) {
  const [tick, setTick] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const seconds = start
    ? Math.max(
        0,
        Math.floor(
          ((end ? new Date(end).getTime() : tick) - new Date(start).getTime()) /
            1000,
        ),
      )
    : 0;
  return (
    <span>
      {Math.floor(seconds / 60)}m {seconds % 60}s elapsed
    </span>
  );
}
function getCleanReproCommand(f) {
  const ev = f?.details?.evidence;
  const target = f?.details?.target || f?.target;
  if (ev?.curl_command) {
    const raw = String(ev.curl_command).trim();
    if (
      (raw.startsWith("curl -X 'GET' -d ''") ||
        raw.startsWith('curl -X GET -d ""') ||
        raw.startsWith('curl "http') ||
        raw.startsWith("curl 'http")) &&
      target
    ) {
      return `curl -i "${target}"`;
    }
    return raw;
  }
  if (target) {
    return `curl -i "${target}"`;
  }
  return "";
}

function FindingDetailsModal({ finding, onClose }) {
  const [copied, setCopied] = useState(false);
  if (!finding) return null;

  const details = finding.details || {};
  const target = details.target || finding.target || "—";
  const status = details.status || "potential";
  const confidence = details.confidence || "scanner-reported";
  const reproCommand = getCleanReproCommand(finding);
  const cvssScore = details.cvss_score;
  const cvssVersion = details.cvss_version;
  const cvssVector =
    details.classification?.["cvss-metrics"] ||
    details.classification?.cvss_metrics ||
    null;

  const rawCwes = details.classification?.["cwe-id"] || details.cwe || [];
  const cweList = (Array.isArray(rawCwes) ? rawCwes : [rawCwes])
    .filter(Boolean)
    .map((c) => String(c).toUpperCase());

  const rawCves = details.cve_id || details.classification?.["cve-id"] || [];
  const cveList = (Array.isArray(rawCves) ? rawCves : [rawCves])
    .filter(Boolean)
    .map((c) => String(c).toUpperCase());

  const references = Array.isArray(details.references)
    ? details.references
    : typeof details.references === "string"
      ? [details.references]
      : [];

  const sources =
    Array.isArray(details.sources) && details.sources.length
      ? details.sources
      : [{ tool: details.source_tool || "scanner", identifier: details.source_identifier || "—" }];

  const copyToClipboard = () => {
    if (!reproCommand) return;
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(reproCommand);
      }
    } catch {
      // clipboard write can fail in restricted environments
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="modal finding-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Finding details"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="finding-modal-header">
          <button
            className="modal-close"
            aria-label="Close details"
            onClick={onClose}
          >
            <X size={18} />
          </button>

          <div className="finding-header-pills" role="group" aria-label="Finding attributes">
            <Badge value={finding.severity} label={`Severity: ${pretty(finding.severity)}`} />

            <span className={`finding-status-badge status-${status}`}>
              {status === "confirmed" ? (
                <CheckCircle2 size={12} aria-hidden="true" />
              ) : status === "informational" ? (
                <Info size={12} aria-hidden="true" />
              ) : (
                <AlertTriangle size={12} aria-hidden="true" />
              )}
              <span>
                {status === "confirmed"
                  ? "Status: Confirmed (evidence verified)"
                  : status === "informational"
                    ? "Status: Informational"
                    : status === "inconclusive"
                      ? "Status: Inconclusive (review required)"
                      : "Status: Potential (manual validation required)"}
              </span>
            </span>

            <span className="finding-confidence-badge" title="Detection confidence level">
              <ShieldCheck size={12} aria-hidden="true" />
              <span>Confidence: {confidence}</span>
            </span>

            {cvssScore != null ? (
              <span className="finding-cvss-badge assessed" title={cvssVector || undefined}>
                <Activity size={12} aria-hidden="true" />
                <span>CVSS {cvssScore}{cvssVersion ? ` (v${cvssVersion})` : ""}</span>
              </span>
            ) : (
              <span className="finding-cvss-badge unassessed" title="No validated CVSS vector provided">
                <Info size={12} aria-hidden="true" />
                <span>CVSS not assessed</span>
              </span>
            )}
          </div>

          <h2 className="finding-modal-title">{finding.title}</h2>
        </div>

        <div className="finding-modal-body">
          {/* Affected Target & Provenance */}
          <div className="finding-card finding-target-card">
            <div className="finding-meta-row">
              <span className="meta-label">Affected endpoint:</span>
              <code className="endpoint-code">{target}</code>
            </div>
            <div className="finding-meta-subgrid">
              <div>
                <span className="meta-label">Detection source:</span>
                <span className="meta-val">
                  {sources.map((s, idx) => (
                    <span key={idx} className="source-item">
                      <strong>{s.tool}</strong> {s.identifier ? `(${s.identifier})` : ""}
                    </span>
                  ))}
                </span>
              </div>
              <div>
                <span className="meta-label">Detected:</span>
                <span className="meta-val">{date(finding.first_seen)}</span>
              </div>
            </div>
          </div>

          {/* Technical Description & Risk */}
          <div className="finding-card">
            <h3 className="section-title">
              <BookOpen size={14} aria-hidden="true" />
              Summary &amp; technical description
            </h3>
            <p className="finding-description">
              {details.description || "Scanner observation; confirm applicability before remediation."}
            </p>
            {details.risk_reason && (
              <div className="risk-reason-box">
                <strong>Risk context &amp; prioritization:</strong>
                <p>{details.risk_reason}</p>
              </div>
            )}
          </div>

          {/* Reproduction Command */}
          {reproCommand && (
            <div className="finding-card finding-repro-card">
              <div className="card-header-with-action">
                <h3 className="section-title">
                  <Terminal size={14} aria-hidden="true" />
                  Reproduction command
                </h3>
                <button
                  type="button"
                  className="btn-copy-repro"
                  onClick={copyToClipboard}
                  aria-label="Copy reproduction command"
                >
                  {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                  <span>{copied ? "Copied!" : "Copy command"}</span>
                </button>
              </div>
              <pre className="repro-code-block">
                <code>{reproCommand}</code>
              </pre>
              <small className="repro-note">
                Executes a non-destructive HTTP request to verify whether the target endpoint reproduces this scanner observation.
              </small>
            </div>
          )}

          {/* Remediation Guidance */}
          <div className="finding-card">
            <h3 className="section-title">
              <ShieldCheck size={14} aria-hidden="true" />
              Remediation guidance
            </h3>
            <p className="remediation-text">
              {details.remediation || "Review evidence and consult official vendor / product security guidance."}
            </p>
          </div>

          {/* Classification & References */}
          <div className="finding-card">
            <h3 className="section-title">
              <FileText size={14} aria-hidden="true" />
              Classification &amp; references
            </h3>
            <div className="classification-pills">
              {cweList.length > 0 && (
                <div className="classification-group">
                  <span className="group-label">CWE:</span>
                  {cweList.map((cwe) => {
                    const cweNum = cwe.replace(/^CWE-?/i, "");
                    return (
                      <a
                        key={cwe}
                        href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="classification-tag cwe"
                        title={`View ${cwe} on MITRE CWE`}
                      >
                        {cwe}
                        <ArrowUpRight size={11} aria-hidden="true" />
                      </a>
                    );
                  })}
                </div>
              )}

              {cveList.length > 0 && (
                <div className="classification-group">
                  <span className="group-label">CVE:</span>
                  {cveList.map((cve) => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="classification-tag cve"
                      title={`View ${cve} on NVD`}
                    >
                      {cve}
                      <ArrowUpRight size={11} aria-hidden="true" />
                    </a>
                  ))}
                </div>
              )}

              {cvssVector && (
                <div className="classification-group">
                  <span className="group-label">CVSS Vector:</span>
                  <code className="vector-code">{cvssVector}</code>
                </div>
              )}

              {cweList.length === 0 && cveList.length === 0 && !cvssVector && (
                <span className="no-classification-note">No external CVE/CWE classification mapped by scanner.</span>
              )}
            </div>

            {references.length > 0 && (
              <div className="references-list">
                <span className="group-label">External references:</span>
                <ul>
                  {references.map((url, idx) => (
                    <li key={idx}>
                      <a href={url} target="_blank" rel="noopener noreferrer" className="reference-link">
                        {url}
                        <ArrowUpRight size={11} aria-hidden="true" />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Raw Technical Evidence (Collapsible) */}
          <details className="finding-raw-evidence">
            <summary className="raw-evidence-summary">
              <span>Raw technical evidence &amp; scanner output</span>
            </summary>
            <div className="raw-evidence-body">
              {details.evidence?.request && (
                <div className="raw-subitem">
                  <strong>HTTP Request sent by scanner:</strong>
                  <pre><code>{details.evidence.request}</code></pre>
                </div>
              )}
              {details.evidence?.info && (
                <div className="raw-subitem">
                  <strong>Scanner diagnostic observation:</strong>
                  <p>{details.evidence.info}</p>
                </div>
              )}
              <div className="raw-subitem">
                <strong>Normalized finding payload:</strong>
                <pre><code>{JSON.stringify(details, null, 2)}</code></pre>
              </div>
            </div>
          </details>
        </div>
      </section>
    </div>
  );
}

function Findings({ id, finished }) {
  const [filters, setFilters] = useState({
      severity: "",
      scanner: "",
      target: "",
      status: "",
      sort: "priority",
    }),
    [page, setPage] = useState(1),
    [selected, setSelected] = useState(null);
  const r = useLoad(
    `/api/scans/${id}/findings?${new URLSearchParams({ ...filters, page: String(page) })}`,
    finished ? 0 : 1500,
  );
  function filter(key, value) {
    setFilters({ ...filters, [key]: value });
    setPage(1);
  }
  return (
    <section className="panel">
      <div className="filters">
        {[
          ["severity", "All severities", severities],
          ["scanner", "All scanners", ["nuclei", "sslyze", "wapiti", "gitleaks", "trivy", "testssl"]],
          ["status", "All statuses", ["potential", "informational", "confirmed", "inconclusive"]],
        ].map(([k, label, options]) => (
          <select
            aria-label={k}
            key={k}
            value={filters[k]}
            onChange={(e) => filter(k, e.target.value)}
          >
            <option value="">{label}</option>
            {options.map((v) => (
              <option key={v} value={v}>
                {pretty(v)}
              </option>
            ))}
          </select>
        ))}
        <input
          aria-label="Filter target"
          placeholder="Filter affected target"
          value={filters.target}
          onChange={(e) => filter("target", e.target.value)}
        />
        <select
          aria-label="Sort findings"
          value={filters.sort}
          onChange={(e) => filter("sort", e.target.value)}
        >
          <option value="priority">Risk priority</option>
          <option value="title">Title</option>
          <option value="target">Target</option>
        </select>
      </div>
      <ErrorBox message={r.error} />
      {r.loading ? (
        <div className="loading">Loading findings…</div>
      ) : r.data?.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Affected target</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {r.data.map((f) => (
                <tr key={f.id}>
                  <td>
                    <button
                      className="finding-link"
                      onClick={() => setSelected(f)}
                    >
                      {f.title}
                      <small>
                        {f.details?.status === "informational"
                          ? "Informational · observation"
                          : f.details?.status === "confirmed"
                          ? "Confirmed · supported by evidence"
                          : f.details?.status === "inconclusive"
                          ? "Inconclusive · requires further review"
                          : "Potential · manual validation required"}
                      </small>
                    </button>
                  </td>
                  <td>
                    <Badge value={f.severity} />
                  </td>
                  <td>{f.details?.target || f.target || "—"}</td>
                  <td>{f.details?.sources?.map((s) => s.tool).join(", ") || f.details?.source_tool || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="No matching findings">
          {finished
            ? "Review execution coverage. No findings does not guarantee the target is secure."
            : "Results appear as available scanners finish."}
        </Empty>
      )}
      <Pagination page={page} total={r.meta?.total || 0} onChange={setPage} />
      {selected && (
        <FindingDetailsModal
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </section>
  );
}
