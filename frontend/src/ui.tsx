import type { CSSProperties } from "react";

export type IconName = "shield" | "grid" | "scan" | "activity" | "folder" | "target" | "layers" | "arrow" | "refresh" | "download" | "check" | "alert" | "file" | "clock" | "chevron" | "spark" | "sun" | "moon";
const paths: Record<IconName, React.ReactNode> = {
  shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
  grid: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  scan: <><path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 12h18" /><path d="M8 8h8v8H8z" opacity=".5" /></>,
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  folder: <path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7h18" />,
  target: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 1v4m0 14v4M1 12h4m14 0h4" /></>,
  layers: <><path d="m12 3 10 5-10 5L2 8l10-5Zm-10 9 10 5 10-5M2 16l10 5 10-5" /></>,
  arrow: <><path d="M5 12h14m-5-5 5 5-5 5" /></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.2 6.2A8 8 0 0 1 20 12M4 12a8 8 0 0 0 13.8 5.8" /></>,
  download: <><path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  alert: <><path d="m12 3 10 18H2L12 3Z" /><path d="M12 9v4m0 3h.01" /></>,
  file: <><path d="M14 2H5v20h14V7l-5-5Z" /><path d="M14 2v5h5M8 12h8m-8 4h6" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  chevron: <path d="m9 5 7 7-7 7" />,
  spark: <><path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z" />,
};
export function Icon({ name, size = 20, className = "" }: { name: IconName; size?: number; className?: string }) {
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
export function Badge({ verdict }: { verdict?: string | null }) {
  const label = verdict ?? "unknown";
  return <span className={`badge badge-${label}`}><span />{label}</span>;
}
export function Notice({ children, tone = "error" }: { children: React.ReactNode; tone?: "error" | "warning" | "info" }) {
  return <div className={`notice notice-${tone}`} role={tone === "error" ? "alert" : "status"}><Icon name="alert" size={17} /><div>{children}</div></div>;
}
export function Radar({ active = false }: { active?: boolean }) {
  return <div className={`radar ${active ? "radar-active" : ""}`} aria-hidden="true"><div className="radar-ring ring-one" /><div className="radar-ring ring-two" /><div className="radar-ring ring-three" /><div className="radar-cross" /><div className="radar-sweep" /><div className="radar-core"><Icon name="shield" size={39} /></div><span className="radar-node node-one" /><span className="radar-node node-two" /><span className="radar-node node-three" /></div>;
}
export function downloadJson(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function humanSize(size?: number | null) {
  if (size == null) return "—";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
export function Metric({ label, value, icon, tone = "mint", note }: { label: string; value: number | null; icon: IconName; tone?: string; note: string }) {
  return <div className="metric" style={{ "--metric-color": `var(--${tone})` } as CSSProperties}><div className="metric-top"><span>{label}</span><Icon name={icon} size={18} /></div><strong>{value === null ? "—" : value.toLocaleString()}</strong><p>{note}</p></div>;
}
