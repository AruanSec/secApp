const BASE = "/api/v1";
let csrf = "";
export interface Session { username: string; csrf: string; is_admin: boolean }
export async function sessionAction(action: "me" | "login" | "register", username?: string, password?: string): Promise<Session> {
  const session = await request<Session>(`/auth/${action}`, action === "me" ? undefined : {
    method: "POST", body: JSON.stringify({ username, password }),
  });
  csrf = session.csrf;
  return session;
}
export async function signOut(): Promise<void> {
  await request("/auth/logout", { method: "POST" });
  csrf = "";
}

export type IoCType = "file" | "hash" | "ip" | "domain" | "url";

export interface ScanResponse {
  scan_id: string;
  type: string;
  value: string;
  verdict: string;
  source: string;
  created_at: string;
  providers: Record<string, string>;
}

export interface JobResult {
  scan_id?: string | null;
  type: string;
  value: string;
  verdict?: string | null;
  error?: string | null;
  path?: string | null;
  size?: number | null;
  skipped?: boolean;
  quarantine_id?: string | null;
  quarantine_status?: string | null;
  quarantine_error?: string | null;
}

export interface JobStatusResponse {
  job_id: string;
  status: string;
  results: JobResult[];
  error?: string | null;
  processed?: number;
  scanned?: number;
  skipped?: number;
  errors?: number;
}

export interface FolderConfig {
  scanner_enabled: boolean;
  max_file_bytes: number;
  max_entries: number;
}

export interface ReportRow {
  owner_username?: string | null;
  scan_id: string;
  type: string;
  value: string;
  verdict: string;
  source: string;
  created_at: string;
}

export interface ReportsResponse {
  page: number;
  page_size: number;
  total: number;
  items: ReportRow[];
}

export interface StatsResponse {
  total_scans: number;
  by_verdict: Record<string, number>;
  by_type: Record<string, number>;
}

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...init?.headers,
      "x-sentinel-request": "1", "x-csrf-token": csrf },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/")) window.dispatchEvent(new Event("sentinel-session-expired"));
    const detail = (body as { detail?: unknown }).detail;
    const message = typeof detail === "string" ? detail :
      Array.isArray(detail) ? detail.map((item: { msg?: string }) => item.msg ?? "Invalid input").join("; ") :
      (body as { error?: { message?: string } }).error?.message ?? `HTTP ${response.status}`;
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export interface AdminUser { id: string; username: string; is_admin: number; created_at: string; scans: number; quarantined: number }
export interface AdminJob { job_id: string; owner_username: string | null; kind: string; status: string; processed: number; files: number }
export interface AdminAudit { id: number; actor_username: string | null; action: string; target_username: string | null; created_at: string }
export const api = {
  providerConfig(signal?: AbortSignal): Promise<{providers: Record<string, boolean>}> {
    return request("/provider-config", {signal});
  },
  adminUsers(page = 1, signal?: AbortSignal): Promise<{total: number; items: AdminUser[]}> { return request(`/admin/users?page=${page}`, {signal}); },
  adminJobs(page = 1, signal?: AbortSignal): Promise<{total: number; items: AdminJob[]}> { return request(`/admin/jobs?page=${page}`, {signal}); },
  adminAudit(page = 1, signal?: AbortSignal): Promise<{total: number; items: AdminAudit[]}> { return request(`/admin/audit?page=${page}`, {signal}); },
  adminJob(id: string): Promise<JobStatusResponse & {files: {path: string; size: number}[]}> { return request(`/admin/jobs/${id}`); },
  adminRole(id: string, is_admin: boolean): Promise<{ok: boolean}> { return request(`/admin/users/${id}/role`, {method: "PATCH", body: JSON.stringify({is_admin})}); },
  adminPassword(id: string, new_password: string): Promise<{ok: boolean}> { return request(`/admin/users/${id}/password`, {method: "POST", body: JSON.stringify({new_password})}); },
  adminRevoke(id: string): Promise<{ok: boolean}> { return request(`/admin/users/${id}/revoke-sessions`, {method: "POST"}); },
  folderConfig(signal?: AbortSignal): Promise<FolderConfig> {
    return request("/folder-config", { signal });
  },
  selectedFolder(files: File[]): Promise<{ job_id: string }> {
    return request("/selected-folder-scan", { method: "POST", body: JSON.stringify({
      files: files.map((file) => ({ path: file.webkitRelativePath || file.name, size: file.size })),
    }) });
  },
  uploadFolderFile(jobId: string, index: number, file: File, maxBytes: number): Promise<{ job_id: string }> {
    return request(`/selected-folder-scan/${jobId}/files/${index}`, {
      method: "PUT", headers: { "content-type": "application/octet-stream" },
      body: file.size > maxBytes ? new Blob() : file,
    });
  },
  cancelSelectedFolder(jobId: string): Promise<{ job_id: string }> {
    return request(`/selected-folder-scan/${jobId}`, { method: "DELETE" });
  },
  scan(type: IoCType, value: string): Promise<ScanResponse> {
    return request("/scan", { method: "POST", body: JSON.stringify({ type, value }) });
  },
  batchScan(iocs: { type: IoCType; value: string }[]): Promise<{ job_id: string }> {
    return request("/batch-scan", { method: "POST", body: JSON.stringify({ iocs }) });
  },
  job(jobId: string, signal?: AbortSignal): Promise<JobStatusResponse> {
    return request(`/scan/${jobId}`, { signal });
  },
  reports(page = 1, pageSize = 20, filters: { type?: string; verdict?: string } = {}, signal?: AbortSignal): Promise<ReportsResponse> {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (filters.type) params.set("type", filters.type);
    if (filters.verdict) params.set("verdict", filters.verdict);
    return request(`/reports?${params}`, { signal });
  },
  quarantine(page = 1, signal?: AbortSignal): Promise<{ total: number; items: QuarantineRow[] }> {
    return request(`/quarantine?${new URLSearchParams({ page: String(page), page_size: "20" })}`, { signal });
  },
  stats(signal?: AbortSignal): Promise<StatsResponse> {
    return request("/stats", { signal });
  },
};


export interface QuarantineRow {
  owner_username?: string | null;
  id: string;
  original_path: string;
  sha256: string;
  size: number;
  origin: string;
  status: string;
  error: string | null;
  created_at: string;
}
