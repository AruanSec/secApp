import { useEffect, useState } from "react";
import { api } from "./api";
import { Icon, Notice } from "./ui";

const PROVIDERS = [
  { id: "virustotal", name: "VirusTotal", variable: "VIRUSTOTAL_API_KEY" },
  { id: "alienvault", name: "AlienVault OTX", variable: "ALIENVAULT_API_KEY" },
  { id: "abusech", name: "MalwareBazaar", variable: "ABUSECH_API_KEY" },
];

export default function ProviderReminder({ isAdmin, refreshKey }: { isAdmin: boolean; refreshKey: number }) {
  const [configured, setConfigured] = useState<Record<string, boolean> | null>(null);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    api.providerConfig(controller.signal).then(value => {
      if (!controller.signal.aborted) { setConfigured(value.providers); setError(false); }
    }).catch(() => {
      if (!controller.signal.aborted) { setConfigured(null); setError(true); }
    });
    return () => controller.abort();
  }, [refreshKey, retry]);
  if (error) return <Notice>Could not check reputation API key setup. <button className="text-button" onClick={() => setRetry(n => n+1)}>Check again</button></Notice>;
  if (!configured) return null;
  const missing = PROVIDERS.filter(provider => !configured[provider.id]);
  if (!missing.length) return null;
  return <section className="panel provider-reminder" aria-labelledby="provider-reminder-heading" role="status">
    <div className="heading-with-icon"><Icon name="alert" /><h2 id="provider-reminder-heading">Set up reputation API keys</h2></div>
    <p>Missing keys: <strong>{missing.map(provider => provider.name).join(", ")}</strong>.</p>
    <p className="field-hint">These providers are skipped until their keys are set. Indicator lookups may return unknown when evidence is unavailable. Folder scanning can still use ClamAV.</p>
    {isAdmin ? <details><summary>How to configure missing keys</summary>
      <p>Add your provider keys to the project’s <code>.env</code> file. If it does not exist, copy <code>.env.example</code> first. Keep your keys private.</p>
      <ul>{missing.map(provider => <li key={provider.id}>{provider.name}: <code>{provider.variable}</code></li>)}</ul>
      <p>Apply the settings from the project folder:</p><pre className="admin-job-details">docker compose up -d --force-recreate backend frontend</pre>
      <p className="field-hint">This restarts the app and interrupts active scan jobs. Then refresh this page. “Set” means a key is present; validity is checked when the provider is queried.</p>
    </details> : <p>Ask your administrator to configure the missing provider keys.</p>}
    <button className="button button-quiet" onClick={() => setRetry(n => n+1)}>Check setup again</button>
  </section>;
}
