import { useEffect, useState } from "react";
import { api, type ReportsResponse } from "./api";
import { Badge, Icon, Notice, downloadJson } from "./ui";

export default function Reports({ refreshKey, showOwner = false }: { refreshKey: number; showOwner?: boolean }) {
  const [page, setPage] = useState(1);
  const [type, setType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [data, setData] = useState<ReportsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(null);
    api.reports(page, 10, { type, verdict }, controller.signal).then((response) => {
      if (!controller.signal.aborted) setData(response);
    }).catch((err) => {
      if (!controller.signal.aborted) { setData(null); setError(err instanceof Error ? err.message : "Could not load scan activity"); }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, type, verdict, refreshKey, retry]);
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / 10));
  return <section id="activity" className="panel activity-panel" aria-busy={loading}>
    <div className="section-heading"><div><span className="eyebrow">THE EVIDENCE TRAIL</span><h2>Scan activity</h2><p className="section-subtitle">Persisted results, ready for review.</p></div><button className="button button-secondary" disabled={!data?.items.length || loading} onClick={() => downloadJson(data, `sentinel-reports-page-${page}.json`)}><Icon name="download" size={16} />Export page</button></div>
    <div className="activity-toolbar"><div className="filter-group"><label htmlFor="report-verdict" className="sr-only">Filter by verdict</label><select id="report-verdict" value={verdict} onChange={(e) => { setVerdict(e.target.value); setPage(1); }}><option value="">All verdicts</option>{["clean", "malicious", "suspicious", "unknown"].map((v) => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}</select><label htmlFor="report-type" className="sr-only">Filter by indicator type</label><select id="report-type" value={type} onChange={(e) => { setType(e.target.value); setPage(1); }}><option value="">All types</option>{["hash", "ip", "domain", "url", "file"].map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}</select></div><span className="quiet-label">{loading ? "Loading records…" : `${(data?.total ?? 0).toLocaleString()} records`}</span></div>
    {error ? <><Notice>{error}</Notice><button className="button button-secondary retry-button" onClick={() => setRetry((n) => n + 1)}><Icon name="refresh" size={16} />Try again</button></> : loading && !data ? <div className="empty-state"><Icon name="refresh" className="spin" size={26} /><h3>Loading scan activity</h3><p>Retrieving your saved verdicts.</p></div> : data?.items.length ? <div className="table-scroll"><table><thead><tr>{showOwner && <th>Owner</th>}<th>Indicator</th><th>Type</th><th>Verdict</th><th>Source</th><th>Time</th></tr></thead><tbody>{data.items.map((row) => <tr key={row.scan_id}>{showOwner && <td>{row.owner_username ?? "Historical / unassigned"}</td>}<td className="table-value mono" title={row.value}>{row.type === "file" ? "Encoded file content" : row.value}</td><td><span className="type-chip">{row.type}</span></td><td><Badge verdict={row.verdict} /></td><td className="source-cell">{row.source === "none" ? "No responding sources" : row.source.split("+").join(" · ")}</td><td className="time-cell">{new Date(row.created_at).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td></tr>)}</tbody></table></div> : <div className="empty-state"><div className="empty-icon"><Icon name="activity" size={30} /></div><h3>{type || verdict ? "No matching scan records" : "Your evidence trail starts here"}</h3><p>{type || verdict ? "Try another type or verdict to find your records." : "Run a scan to build a history of indicators and verdicts."}</p>{type || verdict ? <button className="text-button" onClick={() => { setType(""); setVerdict(""); setPage(1); }}>Clear filters<Icon name="arrow" size={14} /></button> : <a className="text-button" href="#scan-console">Go to scan console<Icon name="arrow" size={14} /></a>}</div>}
    {(data?.total ?? 0) > 0 && <div className="pagination"><span>Page {page} of {totalPages}</span><div><button className="button button-quiet" disabled={page <= 1 || loading} onClick={() => setPage((n) => n - 1)}>Previous</button><button className="button button-quiet" disabled={page >= totalPages || loading} onClick={() => setPage((n) => n + 1)}>Next<Icon name="chevron" size={14} /></button></div></div>}
  </section>;
}
