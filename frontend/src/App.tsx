import { useCallback, useEffect, useState, type FormEvent } from "react";
import DesktopLaunch from "./DesktopLaunch";
import ProviderReminder from "./ProviderReminder";
import AdminPortal from "./AdminPortal";
import FolderScan from "./FolderScan";
import Reports from "./Reports";
import Quarantine from "./Quarantine";
import { sessionAction, signOut, type Session, api, type IoCType, type ScanResponse, type StatsResponse } from "./api";
import { useScanJob } from "./useScanJob";
import { Badge, Icon, Metric, Notice, Radar, downloadJson, type IconName } from "./ui";

const TYPES: { value: IoCType; label: string; placeholder: string }[] = [
  { value: "ip", label: "IP address", placeholder: "8.8.8.8" },
  { value: "domain", label: "Domain", placeholder: "example.com" },
  { value: "url", label: "URL", placeholder: "https://example.com" },
  { value: "hash", label: "Hash", placeholder: "Enter an MD5, SHA-1, SHA-256 or SHA-512 digest" },
  { value: "file", label: "Encoded file", placeholder: "Paste base64-encoded file content" },
];
const MODES: { id: string; label: string; icon: IconName }[] = [
  { id: "folder", label: "Folder scan", icon: "folder" },
  { id: "indicator", label: "Indicator lookup", icon: "target" },
  { id: "batch", label: "Batch scan", icon: "layers" },
];
const PROVIDERS: Record<string, string> = { clamd: "ClamAV", virustotal: "VirusTotal", alienvault: "AlienVault OTX", abusech: "MalwareBazaar" };

type Theme = "light" | "dark";

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const next = theme === "dark" ? "light" : "dark";
  return <button type="button" className="theme-toggle" onClick={onToggle} aria-label={`Use ${next} theme`} title={`Use ${next} theme`}>
    <Icon name={theme === "dark" ? "sun" : "moon"} size={17} />
    <span className="theme-toggle-label">{next === "light" ? "Light" : "Dark"}</span>
  </button>;
}

function IndicatorScan({ onComplete }: { onComplete: () => void }) {
  const [type, setType] = useState<IoCType>("ip");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(null); setResult(null);
    try {
      setResult(await api.scan(type, value.trim()));
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The scan could not be completed");
    } finally { setBusy(false); }
  };
  return <div className="scanner-content">
    <div className="scan-intro"><div><span className="eyebrow">INDICATOR ANALYSIS</span><h2>One indicator.<br /><span>A clearer picture.</span></h2><p>Look up an address, domain, URL or hash<br className="desktop-break" /> and bring the evidence into focus.</p></div><Radar active={busy} /></div>
    <form onSubmit={submit} className="scan-form">
      <label htmlFor="ioc-type">Indicator type</label>
      <div className="input-row"><select id="ioc-type" value={type} disabled={busy} onChange={(e) => { setType(e.target.value as IoCType); setResult(null); }}>{TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}</select><label htmlFor="ioc-value" className="sr-only">Indicator value</label><input id="ioc-value" className="mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder={TYPES.find((t) => t.value === type)?.placeholder} maxLength={4096} required disabled={busy} /><button className="button button-primary" disabled={busy || !value.trim()}><Icon name={busy ? "refresh" : "scan"} className={busy ? "spin" : ""} />{busy ? "Analyzing…" : "Analyze indicator"}</button></div>
      <p className="field-hint">{type === "file" ? "Encoded content is limited to 4,096 characters. Use Folder scan for full files." : "Reputation sources contribute to the verdict. Missing evidence stays unknown."}</p>
    </form>
    {error && <Notice>{error}</Notice>}
    {result && <div className="result-block">
      <div className="section-heading"><div className="heading-with-icon"><Icon name="target" /><h3>Analysis result</h3><Badge verdict={result.verdict} /></div><button className="button button-quiet" onClick={() => downloadJson(result, `sentinel-${result.scan_id}.json`)}><Icon name="download" size={16} />Export result</button></div>
      <p className="result-description">{result.verdict === "unknown" ? "There isn’t enough evidence to classify this indicator. Unknown does not mean clean." : result.verdict === "malicious" ? "A responding source reported a malicious result. Review the indicator before use." : result.verdict === "suspicious" ? "This indicator needs further review based on the available evidence." : "No detections were reported by the responding sources."}</p>
      <details className="value-details"><summary>View submitted {type === "file" ? "content" : "indicator"}</summary><code>{result.value}</code></details>
      <div className="provider-grid">{Object.entries(result.providers).map(([name, verdict]) => <div className="provider-result" key={name}><span>{PROVIDERS[name] ?? name}</span>{verdict === "skipped" ? <span className="quiet-label">Not configured</span> : <Badge verdict={verdict} />}</div>)}</div>
    </div>}
  </div>;
}

function BatchScan({ onComplete }: { onComplete: () => void }) {
  const [text, setText] = useState("");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tracked = useScanJob(onComplete);
  const busy = starting || tracked.active;
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError(null);
    if (lines.length > 1000) { setError("A batch can contain up to 1,000 indicators."); return; }
    const iocs: { type: IoCType; value: string }[] = [];
    for (let index = 0; index < lines.length; index++) {
      const separator = lines[index].indexOf(":");
      const type = lines[index].slice(0, separator).trim();
      const value = lines[index].slice(separator + 1).trim();
      if (separator < 1 || !TYPES.some((t) => t.value === type) || !value) {
        setError(`Entry ${index + 1}: use type:value, with ip, domain, url, hash or file.`); return;
      }
      iocs.push({ type: type as IoCType, value });
    }
    setStarting(true); tracked.reset();
    try { tracked.track((await api.batchScan(iocs)).job_id); }
    catch (err) { setError(err instanceof Error ? err.message : "Could not start this batch"); }
    finally { setStarting(false); }
  };
  return <div className="scanner-content">
    <div className="scan-intro"><div><span className="eyebrow">BULK INDICATOR ANALYSIS</span><h2>More signals.<br /><span>One workspace.</span></h2><p>Analyze multiple indicators in a single job.<br className="desktop-break" /> Follow their results as one collection.</p></div><Radar active={busy} /></div>
    <form onSubmit={submit} className="scan-form"><div className="label-row"><label htmlFor="batch-input">Indicators</label><button className="text-button" type="button" disabled={busy} onClick={() => setText("ip:8.8.8.8\ndomain:example.com\nurl:https://example.com")}>Insert example<Icon name="arrow" size={14} /></button></div><textarea id="batch-input" value={text} onChange={(e) => setText(e.target.value)} rows={5} disabled={busy} required spellCheck={false} placeholder={"ip:8.8.8.8\ndomain:example.com\nurl:https://example.com"} /><div className="form-bottom"><p className="field-hint">One type:value entry per line · {lines.length.toLocaleString()} / 1,000 entries</p><button className="button button-primary" disabled={busy || !lines.length}><Icon name={busy ? "refresh" : "layers"} className={busy ? "spin" : ""} />{busy ? "Processing batch…" : "Start batch scan"}</button></div></form>
    {(error || tracked.error) && <Notice>{error ?? tracked.error}</Notice>}
    {tracked.job && <div className="result-block"><div className="section-heading"><div className="heading-with-icon"><Icon name="activity" /><h3>Batch results</h3><Badge verdict={tracked.job.status} /></div><button className="button button-quiet" disabled={!tracked.job.results.length} onClick={() => downloadJson(tracked.job, `sentinel-batch-${tracked.job?.job_id}.json`)}><Icon name="download" size={16} />Export results</button></div>
      {tracked.job.error && <Notice>{tracked.job.error}</Notice>}
      {tracked.active && <p className="field-hint" role="status">Analyzing indicators. Results will appear when the batch finishes.</p>}
      {tracked.job.results.length > 0 && <div className="table-scroll"><table><thead><tr><th>Type</th><th>Indicator</th><th>Verdict</th></tr></thead><tbody>{tracked.job.results.map((result, index) => <tr key={index}><td><span className="type-chip">{result.type}</span></td><td className="table-value mono" title={result.value}>{result.value}</td><td>{result.error ? <span className="table-error">{result.error}</span> : <Badge verdict={result.verdict} />}</td></tr>)}</tbody></table></div>}
    </div>}
  </div>;
}

function Workspace({ username, isAdmin, onLogout, theme, onThemeToggle }: { username: string; isAdmin: boolean; onLogout: () => void; theme: Theme; onThemeToggle: () => void }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try { return localStorage.getItem("sentinel-sidebar-collapsed") === "true"; }
    catch { return false; }
  });
  useEffect(() => {
    try { localStorage.setItem("sentinel-sidebar-collapsed", String(sidebarCollapsed)); }
    catch { /* Keep the toggle usable when browser storage is unavailable. */ }
  }, [sidebarCollapsed]);
  const [mode, setMode] = useState("folder");
  const [nav, setNav] = useState("scan-console");
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = useCallback(() => setRefreshKey((key) => key + 1), []);
  useEffect(() => {
    const sync = () => {
      const anchor = window.location.hash.slice(1);
      if (["overview", "scan-console", "activity", "quarantine", "admin"].includes(anchor)) setNav(anchor);
    };
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api.stats(controller.signal).then((data) => {
      if (!controller.signal.aborted) { setStats(data); setError(null); }
    }).catch(() => {
      if (!controller.signal.aborted) { setStats(null); setError("Scan statistics are unavailable. Check the connection and try refreshing."); }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [refreshKey]);
  const metrics = stats?.by_verdict;
  const navigation: { id: string; label: string; icon: IconName }[] = [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "scan-console", label: "Scan console", icon: "scan" },
    { id: "activity", label: "Activity log", icon: "activity" },
    { id: "quarantine", label: "Quarantine", icon: "shield" },
  ];
  if (isAdmin) navigation.push({ id: "admin", label: "Admin portal", icon: "shield" });
  return <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
    <a className="skip-link" href="#scan-console">Skip to scan controls</a>
    <aside id="workspace-sidebar" className="sidebar" aria-label="Workspace sidebar">
      <a className="brand" aria-label="Sentinel overview" title={sidebarCollapsed ? "Sentinel overview" : undefined} href="#overview" onClick={() => setNav("overview")}><span className="brand-mark"><Icon name="shield" size={24} /></span><span className="brand-text">SENTINEL<small>SCAN WORKSPACE</small></span></a>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">{navigation.map((item) => <a key={item.id} className={`nav-item ${nav === item.id ? "active" : ""}`} href={`#${item.id}`} onClick={() => setNav(item.id)} aria-current={nav === item.id ? "location" : undefined} aria-label={item.label} title={sidebarCollapsed ? item.label : undefined}><Icon name={item.icon} size={18} /><span className="nav-label">{item.label}</span>{nav === item.id && <span className="nav-dot" />}</a>)}</nav>
      <div className="sidebar-bottom"><div className="local-icon"><Icon name="shield" size={20} /></div><strong>Your files. Your workspace.</strong><p>Inspect locally.<br />Keep the evidence in view.</p><span className="sidebar-tag">LOCAL FILE ANALYSIS</span></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><div className="topbar-left"><button type="button" className="sidebar-toggle" aria-controls="workspace-sidebar" aria-expanded={!sidebarCollapsed} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"} onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}><Icon name="chevron" size={18} className={sidebarCollapsed ? "" : "collapse-chevron"} /></button><div className="breadcrumb">Workspace <Icon name="chevron" size={12} /><span>Security operations</span></div></div><div className="topbar-right"><span className={`connection ${error ? "connection-error" : loading ? "connection-loading" : ""}`}><i />{error ? "Connection issue" : loading ? "Connecting" : "API connected"}</span><ThemeToggle theme={theme} onToggle={onThemeToggle} /><span className="quiet-label">{username}{isAdmin ? " · Admin" : ""}</span><button className="button button-quiet" onClick={onLogout}>Sign out</button></div></header>
      <main className="workspace">
        <DesktopLaunch />
        <section id="overview" className="overview"><div className="page-heading"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>Security, in focus<span>.</span></h1><p>A clear view of your files, indicators and scan evidence.</p></div><button className="button button-secondary" onClick={refresh} disabled={loading}><Icon name="refresh" size={16} className={loading ? "spin" : ""} />Refresh data</button></div>
          <div className="metrics"><Metric label="Total scans" value={stats?.total_scans ?? null} icon="scan" note="Persisted scan records" /><Metric label="Flagged" value={metrics ? (metrics.malicious ?? 0) + (metrics.suspicious ?? 0) : null} icon="alert" tone="amber" note="Malicious or suspicious" /><Metric label="Clean verdicts" value={metrics ? metrics.clean ?? 0 : null} icon="shield" note="No reported detections" /><Metric label="Unknown" value={metrics ? metrics.unknown ?? 0 : null} icon="target" tone="blue" note="Insufficient evidence" /></div>
          {error && <Notice>{error}</Notice>}
        </section>
        <ProviderReminder isAdmin={isAdmin} refreshKey={refreshKey} />
        <section id="scan-console" className="console panel"><div className="console-top"><div className="heading-with-icon"><span className="mini-mark"><Icon name="scan" size={17} /></span><h2>Scan console</h2></div><span className="quiet-label">SELECT A SCAN MODE</span></div><div className="mode-selector" role="group" aria-label="Scan mode">{MODES.map((item) => <button key={item.id} className={mode === item.id ? "selected" : ""} aria-pressed={mode === item.id} onClick={() => setMode(item.id)}><Icon name={item.icon} size={18} />{item.label}<Icon name="chevron" size={13} className="mode-chevron" /></button>)}</div>
          <div hidden={mode !== "folder"}><FolderScan onComplete={refresh} /></div>
          <div hidden={mode !== "indicator"}><IndicatorScan onComplete={refresh} /></div>
          <div hidden={mode !== "batch"}><BatchScan onComplete={refresh} /></div>
          <div className="console-footer"><Icon name="shield" size={15} /><span>Selected files are scanned by the backend. Reputation lookups use hashes.</span><span className="engine-caption">CLAMAV · VT · OTX · MALWAREBAZAAR</span></div>
        </section>
        <Reports refreshKey={refreshKey} showOwner={isAdmin} />
        <Quarantine refreshKey={refreshKey} showOwner={isAdmin} />
        {isAdmin && <AdminPortal username={username} onRefresh={refresh} />}
        <footer className="workspace-footer"><span>SENTINEL <span className="footer-separator">/</span> FILE & INDICATOR ANALYSIS</span><span>Evidence first. Every verdict counts.</span></footer>
      </main>
    </div>
  </div>;
}


export default function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem("sentinel-theme");
      if (saved === "light" || saved === "dark") return saved;
    } catch { /* Use the operating-system preference when storage is unavailable. */ }
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    sessionAction("me").then(setSession).catch(() => setSession(null)).finally(() => setLoading(false));
    const expired = () => { setSession(null); setPassword(""); setError("Your session expired. Sign in again."); };
    window.addEventListener("sentinel-session-expired", expired);
    return () => window.removeEventListener("sentinel-session-expired", expired);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#090e15" : "#eef3f5");
    try { localStorage.setItem("sentinel-theme", theme); }
    catch { /* The selected theme still applies for this session. */ }
  }, [theme]);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null);
    try { setSession(await sessionAction(registering ? "register" : "login", username, password)); setPassword(""); }
    catch (err) { setError(err instanceof Error ? err.message : "Sign-in failed"); }
    finally { setBusy(false); }
  };
  const logout = async () => {
    try { await signOut(); setSession(null); setPassword(""); }
    catch (err) { window.alert(err instanceof Error ? err.message : "Sign-out failed"); }
  };
  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");
  if (loading) return <main className="auth-shell"><ThemeToggle theme={theme} onToggle={toggleTheme} /><p role="status">Loading your workspace…</p></main>;
  if (session) return <Workspace key={session.username} username={session.username} isAdmin={session.is_admin} onLogout={logout} theme={theme} onThemeToggle={toggleTheme} />;
  return <main className="auth-shell"><div className="auth-theme"><ThemeToggle theme={theme} onToggle={toggleTheme} /></div><section className="panel auth-panel">
    <DesktopLaunch />
    <span className="eyebrow">SENTINEL SCAN WORKSPACE</span>
    <h1>{registering ? "Create your account" : "Sign in"}</h1>
    <p>Your scans, reports and quarantine records belong to your account.</p>
    <form className="scan-form" onSubmit={submit}>
      <label htmlFor="username">Username</label>
      <input id="username" value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={64} pattern="[a-zA-Z0-9_.-]+" autoComplete="username" required disabled={busy} />
      <label htmlFor="password">Password</label>
      <input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} maxLength={128} autoComplete={registering ? "new-password" : "current-password"} required disabled={busy} />
      <p className="field-hint">Use at least 12 characters. Usernames accept letters, numbers, dots, underscores and hyphens.</p>
      {error && <Notice>{error}</Notice>}
      <button className="button button-primary" disabled={busy}>{busy ? "Please wait…" : registering ? "Create account" : "Sign in"}</button>
    </form>
    <button className="text-button" disabled={busy} onClick={() => { setRegistering(!registering); setError(null); }}>{registering ? "Already have an account? Sign in" : "Create an account"}</button>
  </section></main>;
}
