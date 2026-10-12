# Sentinel Scan

## Overview

The app is designed to scan IoCs using `clamd` service of `clamav`.

## Tech Stack

### Backend

The backend will be designed with python using `fastAPI`

Package manager should be done with `uv`

Scan data will be saved persistently inside SQLite database.

Malicious IoC will be scanned against `Virustotal`, `alienvault`, `and abuse.ch`

Clean IoCs will be purged after 30 days

### Endpoints:

- `/api/v1/scan` - Single IoC scan
- `/api/v1/batch-scan` - Multiple IoCs scan
- `/api/v1/reports`
- `/api/v1/stats` - Statistics

### Frontend

The UI/UX will be used to send `GET/POST/DELETE/PUT` request to the backend.

To be designed with `vite` and tailwind CSS

## Architecture & Data Flow

```
Client (Vite UI) ──HTTP──▶ FastAPI ──▶ IoC validation
                                   │
                                   ▼
                          Cache lookup (SQLite)
                            │ hit           │ miss
                            ▼               ▼
                     return cached    clamd scan (if file/hash)
                                            │
                                            ▼
                                malicious? ──▶ Query providers
                                             (VirusTotal, AlienVault, abuse.ch)
                                            │
                                            ▼
                                    Persist result (SQLite)
                                            │
                                            ▼
                                  Background purge job (TTL)
```

Flow notes:

- Supported IoC types are validated up front (see IoC Type Matrix).
- A cache lookup avoids re-querying providers for an IoC seen recently.
- `clamd` is used for file/hash inspection; provider lookups enrich the verdict.
- Long-running scans (files, large batches) are dispatched as background jobs and
  polled via a job status endpoint.

## Data Model

| Table | Key fields | Notes |
| --- | --- | --- |
| `ioc` | `id`, `type`, `value`, `created_at`, `updated_at` | Unique on (`type`, `value`) |
| `scan` | `id`, `ioc_id`, `verdict`, `source`, `status`, `created_at` | One IoC can have many scans over time |
| `scan_result` | `id`, `scan_id`, `provider`, `verdict`, `raw` (JSON), `created_at` | Per-provider enrichment result |
| `purge_log` | `id`, `run_at`, `deleted_count` | Audit of TTL cleanup runs |

- `verdict` values: `clean`, `malicious`, `suspicious`, `unknown`, `error`.
- `status` values: `pending`, `running`, `completed`, `failed`.
- Persist a `ttl_expires_at` on clean records; the purge job deletes expired rows.

## API Specification

### `POST /api/v1/scan`
Request:
```json
{ "type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f" }
```
Response `200`:
```json
{ "scan_id": "uuid", "verdict": "malicious", "providers": { "virustotal": "malicious" } }
```

### `POST /api/v1/batch-scan`
Request:
```json
{ "iocs": [ { "type": "ip", "value": "8.8.8.8" }, { "type": "domain", "value": "example.com" } ] }
```
Response `202` (async) returns a `job_id`; poll `/api/v1/scan/{job_id}`.

### `GET /api/v1/reports`
Query params: `type`, `verdict`, `from`, `to`, `page`, `page_size`.
Returns a paginated list of scans.

### `GET /api/v1/stats`
Returns aggregate metrics: total scans, counts by verdict, by type, and a time range.

### Errors
Standard error envelope: `{ "error": { "code": "...", "message": "..." } }`
Codes: `400` invalid IoC, `401` unauthorized, `404` not found, `429` rate limited, `500` internal.

## IoC Type Matrix

| IoC type | clamd | VirusTotal | AlienVault OTX | abuse.ch |
| --- | --- | --- | --- | --- |
| file | yes | yes (hash) | yes | yes |
| hash | no | yes | yes | yes |
| ip | no | yes | yes | no |
| domain | no | yes | yes | no |
| url | no | yes | yes | no |

## Configuration & Secrets

Environment variables (via `.env`, never committed):

| Variable | Purpose |
| --- | --- |
| `CLAMD_HOST` / `CLAMD_PORT` | clamd connection |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `ALIENVAULT_API_KEY` | AlienVault OTX API key |
| `ABUSECH_API_KEY` | abuse.ch API key |
| `DATABASE_URL` | SQLite path |
| `CLEAN_TTL_DAYS` | Purge window (default `30`) |

## Security & Operations

- Authentication/authorization on all write endpoints; scope scan vs. reports access.
- Rate limiting per client and outbound throttling to respect provider quotas.
- Cache provider results to avoid duplicate external calls.
- Structured logging and metrics (OpenTelemetry) for scans and provider calls.
- Docker/Compose deployment; the app reaches `clamd` over the internal network.
- Purge job runs on a schedule (e.g. APScheduler or cron) and is audited in `purge_log`.

## Testing

- Unit tests with `pytest`; integration tests against a stubbed `clamd` and mock providers.
- Target meaningful coverage on validation, verdict logic, and TTL purge.
- Linting/formatting with `ruff`.
- CI runs lint + tests; deploy to staging before merging to main.

## Coding Workflow

Before making any changes to code, perform the following as specified below:

1. Always ensure that the local repo is in sync with the remote if any.
 2. create a feature branch, finish off all the coding before merging to the main branch.
 3. Test the code in staging branch before pushing to remote.
