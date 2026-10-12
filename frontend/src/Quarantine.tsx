import { useEffect, useState } from "react";
import { api, type QuarantineRow } from "./api";
import { Icon, Notice, humanSize } from "./ui";

export default function Quarantine({ refreshKey, showOwner = false }: { refreshKey: number; showOwner?: boolean }) {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<{ total: number; items: QuarantineRow[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(null);
    api.quarantine(page, controller.signal).then((value) => {
      if (!controller.signal.aborted) setData(value);
    }).catch((err) => {
      if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Could not load quarantine");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, refreshKey, retry]);
  return <section id="quarantine" className="panel activity-panel">
    <div className="section-heading"><div className="heading-with-icon"><Icon name="shield" /><h2>Quarantine</h2></div><button className="button button-quiet" disabled={loading} onClick={() => setRetry((value) => value + 1)}><Icon name="refresh" size={16} />Refresh</button></div>
    <p className="field-hint">Malicious files are isolated in backend storage. Uploaded copies leave the original on your computer. Quarantined contents cannot be opened from this app.</p>
    {error && <Notice>{error}</Notice>}
    {loading ? <p className="field-hint" role="status">Loading quarantine…</p> : !error && (data?.items.length ? <>
      <div className="table-scroll"><table><thead><tr>{showOwner && <th>Owner</th>}<th>Original file</th><th>Size</th><th>Action</th><th>Quarantined</th></tr></thead><tbody>{data.items.map((item) => <tr key={item.id}>{showOwner && <td>{item.owner_username ?? "Historical / unassigned"}</td>}<td><span className="mono" title={`SHA-256: ${item.sha256}`}>{item.original_path}</span>{item.error && <div className="table-error">{item.error}</div>}</td><td>{humanSize(item.size)}</td><td>{item.status === "moved" ? "Original moved" : item.status === "removing" ? "Copy stored; source removal unconfirmed" : "Copy stored; original remains"}</td><td>{new Date(item.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>
      <div className="pagination"><span>{data.total.toLocaleString()} quarantined files</span><div><button className="button button-quiet" disabled={page === 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button className="button button-quiet" disabled={page * 20 >= data.total} onClick={() => setPage((value) => value + 1)}>Next</button></div></div>
    </> : <div className="small-empty">No files in quarantine.</div>)}
  </section>;
}
