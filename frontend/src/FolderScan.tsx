import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, type FolderConfig } from "./api";
import { useScanJob } from "./useScanJob";
import { Badge, Icon, Notice, Radar, downloadJson, humanSize } from "./ui";

export default function FolderScan({ onComplete }: { onComplete: () => void }) {
  const [config, setConfig] = useState<FolderConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [configError, setConfigError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const [files, setFiles] = useState<File[]>([]);
  const [uploaded, setUploaded] = useState(0);
  const picker = useRef<HTMLInputElement>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const tracked = useScanJob(onComplete);
  const { job } = tracked;
  const busy = starting || tracked.active;

  useEffect(() => {
    const controller = new AbortController();
    setConfigLoading(true); setConfigError(null);
    api.folderConfig(controller.signal).then((value) => {
      if (!controller.signal.aborted) setConfig(value);
    }).catch(() => {
      if (!controller.signal.aborted) setConfigError("Could not connect to the scan backend. Try again.");
    }).finally(() => { if (!controller.signal.aborted) setConfigLoading(false); });
    return () => controller.abort();
  }, [retry]);

  const ready = config?.scanner_enabled && !configError && files.length > 0;
  const start = async (event: FormEvent) => {
    event.preventDefault(); setError(null);
    if (!config || !files.length) { setError("Choose a folder containing files first."); return; }
    if (files.length > config.max_entries) { setError(`Select a folder with at most ${config.max_entries.toLocaleString()} files.`); return; }
    setStarting(true); tracked.reset(); setFilter(""); setUploaded(0);
    let jobId: string | null = null;
    try {
      jobId = (await api.selectedFolder(files)).job_id;
      tracked.track(jobId);
      for (let index = 0; index < files.length; index++) {
        await api.uploadFolderFile(jobId, index, files[index], config.max_file_bytes);
        setUploaded(index + 1);
      }
    } catch (err) {
      if (jobId) await api.cancelSelectedFolder(jobId).catch(() => {});
      setError(err instanceof Error ? err.message : "Could not upload the selected folder");
    } finally { setStarting(false); }
  };

  const results = job?.results ?? [];
  const classification = (result: typeof results[number]) => result.skipped ? "skipped" : result.error ? "error" : result.verdict ?? "unknown";
  const filtered = filter ? results.filter((result) => classification(result) === filter) : results;
  const flagged = results.filter((result) => ["malicious", "suspicious"].includes(result.verdict ?? "")).length;
  const quarantineFailures = results.filter((result) => result.quarantine_error).length;
  const unknown = results.filter((result) => result.verdict === "unknown").length;

  return <div className="scanner-content">
    <div className="scan-intro"><div><span className="eyebrow">RECURSIVE FILE ANALYSIS</span><h2>A deeper look.<br /><span>A clearer verdict.</span></h2><p>Choose a folder and inspect every level.<br className="desktop-break" /> Keep every result within reach.</p></div><Radar active={busy} /></div>
    <form onSubmit={start} className="folder-form">
      <div className="folder-target local-folder-target"><div className="folder-symbol"><Icon name="folder" size={28} /></div><div className="folder-target-name"><span className="eyebrow">SELECTED FOLDER</span><strong>{files.length ? files[0].webkitRelativePath.split("/")[0] : "Choose a folder to scan"}</strong><span>{files.length ? `${files.length.toLocaleString()} files, including nested folders` : "Select a folder on your computer"}</span></div>
        <button type="button" className="button button-quiet" disabled={busy} onClick={() => picker.current?.click()}><Icon name="folder" size={16} />Choose folder</button>
        <input ref={picker} type="file" className="sr-only" tabIndex={-1} aria-label="Choose folder to scan" disabled={busy} multiple {...{ webkitdirectory: "", directory: "" }} onChange={(event) => {
          const selected = Array.from(event.target.files ?? []);
          setFiles(selected); setError(selected.length ? null : "This folder contains no files to scan.");
          event.target.value = "";
        }} />
      </div>
      <p className="field-hint">Files in the selected folder and its subfolders are sent to the scan backend. Malicious copies are stored in quarantine; originals on your computer remain in place. Empty folders are not included.</p>
      {!configLoading && (configError || !config?.scanner_enabled) && <Notice tone="warning">{configError ?? "Connect ClamAV before starting a file scan."}<button type="button" className="text-button inline-retry" onClick={() => setRetry((n) => n + 1)}>Retry connection<Icon name="refresh" size={14} /></button></Notice>}
      <div className="folder-controls"><span className="field-hint" role="status">{starting ? `Uploading and scanning ${uploaded.toLocaleString()} / ${files.length.toLocaleString()} files…` : "All nested files are included automatically."}</span><button className="button button-primary scan-cta" disabled={!ready || busy}><Icon name={busy ? "refresh" : "scan"} className={busy ? "spin" : ""} />{busy ? "Scanning folder…" : "Start recursive scan"}<Icon name="arrow" size={17} /></button></div>
      <div className="scan-limits"><span><Icon name="layers" size={14} />Includes subfolders</span>{config && <><span><Icon name="file" size={14} />{humanSize(config.max_file_bytes)} per file</span><span><Icon name="grid" size={14} />{config.max_entries.toLocaleString()} file limit</span></>}</div>
    </form>
    {(error || tracked.error) && <Notice>{error ?? tracked.error}</Notice>}
    {job && <div className="result-block folder-results" aria-busy={tracked.active}>
      <div className="section-heading"><div className="heading-with-icon"><Icon name="activity" /><h3>Scan results</h3><Badge verdict={job.status} /></div><button className="button button-quiet" disabled={!results.length} onClick={() => downloadJson(job, `sentinel-folder-${job.job_id}.json`)}><Icon name="download" size={16} />Export results</button></div>
      <div className="job-summary" aria-live="polite"><div><strong>{job.scanned ?? 0}</strong><span>Scanned</span></div><div className={flagged ? "summary-flagged" : ""}><strong>{flagged}</strong><span>Flagged</span></div><div><strong>{job.skipped ?? 0}</strong><span>Skipped</span></div><div><strong>{job.errors ?? 0}</strong><span>Errors</span></div></div>
      {tracked.active && <div className="scan-running" role="status"><span className="activity-dot" />Inspecting files in the selected folder. Results appear as files finish.</div>}
      {job.error && <Notice>{job.error}</Notice>}
      {quarantineFailures > 0 && <Notice tone="warning">{quarantineFailures} file(s) could not be fully quarantined. Review the quarantine details.</Notice>}
      {job.status === "completed" && (job.skipped ?? 0) > 0 && <Notice tone="warning">{job.scanned ? `${job.skipped} item(s) were skipped.` : "No files were inspected."} Skipped files have no antivirus verdict. Review the details below.</Notice>}
      {job.status === "completed" && unknown > 0 && <Notice tone="info">{unknown} file(s) have an unknown verdict. Insufficient evidence does not mean clean.</Notice>}
      {results.length > 0 && <><div className="results-toolbar"><span className="quiet-label">{results.length.toLocaleString()} FILE RESULTS</span><label htmlFor="folder-result-filter" className="sr-only">Filter folder results</label><select id="folder-result-filter" value={filter} onChange={(e) => setFilter(e.target.value)}><option value="">All results</option>{["malicious", "suspicious", "clean", "unknown", "skipped", "error"].map((v) => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}</select></div>{filtered.length ? <div className="table-scroll folder-table"><table><thead><tr><th>File</th><th>Size</th><th>Verdict</th><th>Quarantine</th><th>Detail</th></tr></thead><tbody>{filtered.slice(-200).map((result, index) => <tr key={`${result.path}-${index}`}><td><div className="file-cell"><Icon name="file" size={17} /><span className="mono">{result.path}</span></div></td><td className="size-cell mono">{humanSize(result.size)}</td><td><Badge verdict={classification(result)} /></td><td title={result.quarantine_error ?? undefined}>{result.quarantine_status === "copy" ? "Copy stored; original remains" : result.quarantine_status === "failed" ? "Quarantine failed" : "—"}{result.quarantine_error && <div className="table-error">{result.quarantine_error}</div>}</td><td className="detail-cell" title={result.error ?? result.value}>{result.error ?? (result.value ? `SHA-256: ${result.value}` : "—")}</td></tr>)}</tbody></table></div> : <div className="small-empty">No results match this verdict.</div>}{filtered.length > 200 && <p className="field-hint">Showing the latest 200 matching files. Export results for the complete list.</p>}</>}
      {job.status === "completed" && !results.length && <div className="empty-state compact"><Icon name="folder" size={26} /><h3>No files found</h3><p>Choose a folder containing regular files to inspect.</p></div>}
    </div>}
  </div>;
}
