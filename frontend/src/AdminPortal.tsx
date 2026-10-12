import { useEffect, useState, type FormEvent } from "react";
import { api, type AdminUser, type AdminJob, type AdminAudit } from "./api";
import { Badge, Notice, downloadJson } from "./ui";

function Pager({ page, total, setPage }: { page: number; total: number; setPage: (page: number) => void }) {
  return <div className="pagination"><span>{total} records · Page {page}</span><div><button className="button button-quiet" disabled={page === 1} onClick={() => setPage(page-1)}>Previous</button><button className="button button-quiet" disabled={page*20 >= total} onClick={() => setPage(page+1)}>Next</button></div></div>;
}

export default function AdminPortal({ username, onRefresh }: { username: string; onRefresh: () => void }) {
  const [users, setUsers] = useState<{total: number; items: AdminUser[]}>({total: 0, items: []});
  const [jobs, setJobs] = useState<{total: number; items: AdminJob[]}>({total: 0, items: []});
  const [audit, setAudit] = useState<{total: number; items: AdminAudit[]}>({total: 0, items: []});
  const [userPage, setUserPage] = useState(1);
  const [jobPage, setJobPage] = useState(1);
  const [auditPage, setAuditPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [passwordUser, setPasswordUser] = useState<AdminUser | null>(null);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [success, setSuccess] = useState<string | null>(null);
  const [details, setDetails] = useState<Awaited<ReturnType<typeof api.adminJob>> | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true); setError(null);
    Promise.all([api.adminUsers(userPage, controller.signal), api.adminJobs(jobPage, controller.signal), api.adminAudit(auditPage, controller.signal)])
      .then(([u,j,a]) => { if (!controller.signal.aborted) { setUsers(u); setJobs(j); setAudit(a); } })
      .catch(err => { if (!controller.signal.aborted) { setUsers({total:0,items:[]}); setJobs({total:0,items:[]}); setAudit({total:0,items:[]}); setError(err instanceof Error ? err.message : "Could not load admin portal"); } })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [userPage, jobPage, auditPage, revision]);
  const act = async (operation: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await operation(); setRevision(n => n+1); onRefresh(); }
    catch (err) { setError(err instanceof Error ? err.message : "Action failed"); }
    finally { setBusy(false); }
  };
  const changePassword = async (event: FormEvent) => {
    event.preventDefault();
    if (!passwordUser) return;
    if (password !== confirmation) { setError("The passwords do not match."); return; }
    setBusy(true); setError(null); setSuccess(null);
    try {
      await api.adminPassword(passwordUser.id, password);
      setSuccess(`Password changed for ${passwordUser.username}. Their sessions have been revoked.`);
      setPasswordUser(null); setPassword(""); setConfirmation("");
      setRevision(n => n+1);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not change password"); }
    finally { setBusy(false); }
  };
  return <section id="admin" className="panel activity-panel" aria-busy={busy}>
    <div className="section-heading"><div><span className="eyebrow">ADMINISTRATION</span><h2>Admin portal</h2><p className="section-subtitle">Full workspace access across all accounts. Reports, statistics and quarantine above include historical records.</p></div><button className="button button-secondary" disabled={busy} onClick={() => { setRevision(n => n+1); onRefresh(); }}>Refresh all</button></div>
    {error && <Notice>{error}</Notice>}
    {success && <p role="status">{success}</p>}
    <h3>Accounts</h3><p className="field-hint">Password and role changes revoke the account’s sessions. The last administrator cannot be demoted.</p>
    <div className="table-scroll"><table><thead><tr><th>Username</th><th>Role</th><th>Scans</th><th>Quarantine</th><th>Actions</th></tr></thead><tbody>{users.items.map(user => <tr key={user.id}><td>{user.username}</td><td>{user.is_admin ? "Administrator" : "User"}</td><td>{user.scans}</td><td>{user.quarantined}</td><td><button className="button button-quiet" disabled={busy || user.username === username} onClick={() => { setPasswordUser(user); setPassword(""); setConfirmation(""); setError(null); setSuccess(null); }}>Change password</button><button className="button button-quiet" disabled={busy || user.username === username} onClick={() => { if (window.confirm(`${user.is_admin ? "Remove" : "Grant"} administrator access for ${user.username}? Their sessions will be revoked.`)) void act(() => api.adminRole(user.id, !user.is_admin)); }}>{user.is_admin ? "Remove admin" : "Make admin"}</button><button className="button button-quiet" disabled={busy || user.username === username} onClick={() => { if (window.confirm(`Sign ${user.username} out of all sessions?`)) void act(() => api.adminRevoke(user.id)); }}>Revoke sessions</button></td></tr>)}</tbody></table></div>
    {passwordUser && <form className="scan-form result-block" onSubmit={changePassword}>
      <h3>Change password for {passwordUser.username}</h3>
      <p className="field-hint">Use 12–128 characters. This signs the user out of all sessions.</p>
      <label htmlFor="admin-new-password">New password</label>
      <input id="admin-new-password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required disabled={busy} value={password} onChange={e => setPassword(e.target.value)} />
      <label htmlFor="admin-confirm-password">Confirm new password</label>
      <input id="admin-confirm-password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required disabled={busy} value={confirmation} onChange={e => setConfirmation(e.target.value)} />
      <div className="form-bottom"><button className="button button-primary" disabled={busy}>Save password</button><button type="button" className="button button-quiet" disabled={busy} onClick={() => { setPasswordUser(null); setPassword(""); setConfirmation(""); setError(null); }}>Cancel</button></div>
    </form>}
    <Pager page={userPage} total={users.total} setPage={setUserPage} />
    <h3>Scan jobs</h3><p className="field-hint">Jobs are held in memory and disappear when the backend restarts.</p>
    <div className="table-scroll"><table><thead><tr><th>Owner</th><th>Job</th><th>Kind</th><th>Status</th><th>Progress</th><th>Actions</th></tr></thead><tbody>{jobs.items.map(job => <tr key={job.job_id}><td>{job.owner_username ?? "Historical / unassigned"}</td><td className="mono">{job.job_id}</td><td>{job.kind}</td><td><Badge verdict={job.status} /></td><td>{job.processed}{job.kind === "upload" ? ` / ${job.files}` : ""}</td><td><button className="button button-quiet" disabled={busy} onClick={() => void act(async () => setDetails(await api.adminJob(job.job_id)))}>View results</button>{job.kind === "upload" && ["pending", "running"].includes(job.status) && <button className="button button-quiet" disabled={busy} onClick={() => void act(() => api.cancelSelectedFolder(job.job_id))}>Cancel upload</button>}</td></tr>)}</tbody></table></div>
    <Pager page={jobPage} total={jobs.total} setPage={setJobPage} />
    {details && <div className="result-block"><div className="section-heading"><h3>Job {details.job_id}</h3><button className="button button-quiet" onClick={() => downloadJson(details, `sentinel-admin-job-${details.job_id}.json`)}>Export job</button><button className="button button-quiet" onClick={() => setDetails(null)}>Close</button></div><pre className="admin-job-details">{JSON.stringify(details, null, 2)}</pre></div>}
    <h3>Administrator actions</h3><div className="table-scroll"><table><thead><tr><th>Actor</th><th>Action</th><th>Account</th><th>Time</th></tr></thead><tbody>{audit.items.map(event => <tr key={event.id}><td>{event.actor_username ?? "Host administrator"}</td><td>{event.action}</td><td>{event.target_username ?? "Unknown account"}</td><td>{new Date(event.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>
    <Pager page={auditPage} total={audit.total} setPage={setAuditPage} />
  </section>;
}
