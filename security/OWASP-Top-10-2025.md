# OWASP Top 10 assessment

> Historical snapshot taken before authentication was implemented. Current access-control, session, CSRF and ownership regression coverage is in `backend/tests/test_auth.py`; see README for the new account behavior. Other findings still require their own remediation.

Assessment date: 2026-10-11. Framework: [OWASP Top 10:2025](https://top10.owasp.org/2025/).

## Authentication remediation update

Authentication and ownership have now been implemented. 74 backend regression tests
pass, including cross-account denial for jobs, upload/cancel actions, reports,
statistics, quarantine and cache reuse. Live nginx checks passed for registration,
login, session cookies, CSRF/origin rejection, no-store responses, and logout; the
temporary live test account was removed. The web build and Electron configuration
tests passed. Visual browser verification was unavailable because the in-app browser
failed to attach.

The updated isolated probes pass **19 of 21** expectations; see
[post-authentication results](post-auth-assessment.json). The remaining failed probe
expectations are terminal-job eviction and exception redaction. Dependency upgrades,
web CSP/header hardening and security alerting still require separate work. These
probes are a bounded sample, not an overall security score.

## Scope and result

Reviewed the FastAPI backend, nginx/React web frontend, Electron wrapper, Docker configuration, upload/quarantine handling, and locked Python/npm dependencies. Read-only HTTP checks used the running localhost frontend. Mutating probes ran in a separate backend process against a temporary SQLite database and quarantine directory, with external providers and scanner failures mocked. Live reports, quarantine files, and user files were not changed. Product code was not changed as part of this assessment.

21 targeted API probes returned 13 expected protections and 8 failed control expectations. The latter overlap across the six findings below; this is not an OWASP compliance score. Existing backend tests: **66 passed**, with one deprecation warning. No critical exploit, remote code execution, or confirmed browser-based attack was demonstrated.

The deployment binds the frontend to 127.0.0.1, with backend and ClamAV ports internal to Docker. This substantially limits network exposure. Ratings below assume this local desktop deployment; a shared or externally exposed deployment raises the access-control and availability risks.

## Findings and recommended order

### F01 — API has no authentication or ownership checks (Medium locally; High if shared)

Anonymous requests to reports and quarantine metadata return 200. An anonymously created job can be read without credentials; routes contain no user/session ownership model. OpenAPI also returns 200, which is an informational exposure rather than a separate vulnerability.

Evidence: `unauthenticated ...` and `job ownership enforced` in [API results](api-assessment.json); backend/app/main.py and backend/app/api/routes.py.

For local use, add a server-issued session/bootstrap secret and protect every API action, including job reads, cancellation, reports, and quarantine metadata. For shared use, add authenticated users and explicit resource ownership. Keep bootstrap secrets out of URLs and access logs. This is an architectural access-control gap; the probe did not demonstrate theft of another user's live records.

### F02 — Unexpected Host/Origin accepted, including a cross-origin-shaped POST (Medium)

The live nginx endpoint accepts `Host: audit.invalid`. In the isolated backend, a POST carrying `Origin: https://audit.invalid` and raw JSON with no Content-Type starts a folder job (202). This request shape avoids the usual JSON preflight requirement. CORS preflight does not grant arbitrary origins, but CORS alone does not prevent side effects.

Evidence: `untrusted Host rejected` and `cross-origin POST without Content-Type blocked` in [API results](api-assessment.json); live /api/v1/stats returned 200 with an unexpected Host and Origin.

Allowlist valid Host values and intended frontend origins. Reject unexpected Origin on mutations, require the documented JSON Content-Type, and add session-bound CSRF protection where appropriate. Treat Electron and web access consistently. DNS rebinding and an actual hostile website/browser chain were **not** exercised; browser private-network policies may further restrict reachability. Confirmed evidence is server acceptance, not a complete browser exploit.

### F03 — Job retention and work admission are unbounded (Medium)

Eight sequentially created and cancelled folder jobs remain in the process-global JOBS dictionary. Source review found no terminal-job eviction, global job cap, request rate limit, or equivalent admission bound for batch jobs. Existing upload limits help with individual payloads but do not bound cumulative memory or batch work.

Evidence: `terminal jobs bounded or evicted` in [API results](api-assessment.json); backend/app/api/routes.py JOBS and batch-scan handling.

Expire terminal jobs, cap retained manifests/results, limit concurrent work, and rate-limit job creation. Bound batch size and reject overload with a clear response. Only eight tiny jobs were used: memory exhaustion and sustained load were not attempted.

### F04 — Web responses lack browser hardening headers (Low/Medium)

The live HTML response has no Content-Security-Policy, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, or Permissions-Policy. Sensitive API responses also lack an explicit no-store policy. Missing headers are defense-in-depth gaps, not evidence that XSS or clickjacking was exploited.

Evidence: live `curl -D -` checks; frontend/nginx.conf. Electron injects its own CSP and enables context isolation, sandboxing, and disabled Node integration, so its header posture differs from the web frontend.

Add a tested web CSP with `frame-ancestors 'none'`, nosniff, a restrictive referrer/permissions policy, and no-store for sensitive API data. Keep policies compatible with the app's requests and assets. Require TLS if deployed beyond trusted loopback; local HTTP alone is not a demonstrated cryptographic failure.

### F05 — Pinned Starlette has seven known advisory families (Component risk)

OSV checked 29 Python registry packages in backend/uv.lock. It returned 14 records representing **seven distinct CVE advisory families**, all affecting Starlette 0.41.3. Frontend and desktop npm audits each returned zero known vulnerabilities at assessment time. A clean advisory audit does not establish supply-chain integrity.

| Advisory | First patched version reported by OSV | Feature/reachability review |
| --- | --- | --- |
| [CVE-2025-54121](https://github.com/Kludex/starlette/security/advisories/GHSA-2c2j-9gv5-cj73) | 0.47.2 | Multipart parsing DoS; app uses raw streams, no multipart/form endpoint found. |
| [CVE-2025-62727](https://github.com/Kludex/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8) | 0.49.1 | FileResponse Range merging DoS; app does not use FileResponse, static files served by nginx. |
| [CVE-2026-54283](https://github.com/Kludex/starlette/security/advisories/GHSA-82w8-qh3p-5jfq) | 1.3.1 | URL-encoded form parsing limits; no request.form use found. |
| [CVE-2026-48710](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr) | 1.0.1 | Host poisoning of request.url path interpretation; no such security checks found. F02 remains an independent host-validation gap. |
| [CVE-2026-54282](https://github.com/Kludex/starlette/security/advisories/GHSA-jp82-jpqv-5vv3) | 1.3.0 | Request URL hostname interpretation; no request.url hostname-based security check found. |
| [CVE-2026-48818](https://github.com/Kludex/starlette/security/advisories/GHSA-wqp7-x3pw-xc5r) | 1.1.0 | Windows StaticFiles UNC handling; backend runs Linux and does not mount StaticFiles. |
| [CVE-2026-48817](https://github.com/Kludex/starlette/security/advisories/GHSA-x746-7m8f-x49c) | 1.1.0 | HTTPEndpoint method dispatch; app uses FastAPI function routes. |

Evidence: [raw OSV output](python-dependency-audit.json), with aliases, affected ranges, and source references. No advisory exploit was demonstrated. Upgrade FastAPI and Starlette together to compatible patched releases, regenerate the lockfile, and run regression/security probes; do not blindly override FastAPI's Starlette constraint. Add recurring dependency checks to CI.

### F06 — Batch failures expose raw exception text (Low/Medium)

A deliberately mocked scanner exception containing `SECURITY_AUDIT_INTERNAL_DETAIL` was returned verbatim in job.error. Per-file batch failures also use str(exc) in source. Real exceptions could contain internal paths or service details, although no actual credential or private-data leakage was demonstrated.

Evidence: `internal batch exceptions are redacted` in [API results](api-assessment.json); backend/app/api/routes.py and backend/app/services/scanner.py.

Return a stable public error code/message and a correlation ID. Keep detailed tracebacks in restricted server logs and redact secrets from them.

## Coverage of all ten categories

| OWASP category | Assessment outcome |
| --- | --- |
| A01 Broken Access Control | F01/F02. Five traversal-shaped upload paths rejected with 400; quarantine payload URL returned 404. |
| A02 Security Misconfiguration | F02/F04. Loopback binding, internal service ports, nonroot/read-only backend and reduced container privileges are positive controls. |
| A03 Software Supply Chain Failures | F05. Lockfiles reviewed and Python/npm audits run. Container base-image/package CVEs, provenance, signing, and CI compromise not assessed. |
| A04 Cryptographic Failures | No demonstrated break. Providers use fixed HTTPS hosts with normal certificate validation. Local HTTP and unencrypted SQLite/quarantine storage reviewed; disk encryption and external TLS deployment not verified. |
| A05 Injection | SQL-injection-shaped report filters returned zero rows and preserved the table. Traversal rejected. React escaping reviewed; browser DOM XSS was not dynamically tested. Mocked OTX URL indicator kept its outbound host fixed; other providers reviewed in source, no full SSRF campaign performed. |
| A06 Insecure Design | F03. Upload limits exist: streamed bytes over a reduced test limit return 413; declared oversized files are skipped. Whole-app resource bounds are incomplete. |
| A07 Authentication Failures | F01. No authentication feature exists to test password/reset/session controls. Relevant if protection is expected even for local use. |
| A08 Software or Data Integrity Failures | Generated quarantine names, restrictive permissions, stream-size validation, lockfiles and database handling reviewed. No integrity bypass demonstrated. Artifact signing, poisoned provider results, and build provenance remain untested. |
| A09 Security Logging and Alerting Failures | Runtime errors logged. No application-level structured security audit trail or alerts found for rejected requests, job ownership/actions or quarantine operations. External log collection/alerting not assessed. Add correlation IDs, redaction, and security events. |
| A10 Mishandling of Exceptional Conditions | F06. Invalid inputs produce 400/422; oversized streaming produces 413 with a failed job. Existing regression tests exercise quarantine/error paths. Crash, disk-full, restart/recovery and sustained overload fault injection not performed. |

## Reproduce and extend

The API probe intentionally exits successfully even when controls fail; read `control_passed` and the totals. It runs against the application imported in a separate process, never the live ASGI process's job dictionary. Scanner/provider behaviors are mocked where specified.

```bash
docker compose exec -T backend /app/lib/bin/python < security/assess_api.py
python3 security/check_python_dependencies.py
cd frontend && npm audit --json
# From repository root:
cd desktop && npm audit --json
```

The dependency script needs internet access and exits 1 when advisories exist. Current captured API results are [JSON](api-assessment.json) and [full output](api-assessment-output.log). These are snapshots; advisory databases and installed images may change. Re-run after fixes and retain negative probes for access, origin, resource bounds, and redaction.

This bounded local review is not a comprehensive penetration test or certification. Browser exploitation, exhaustive endpoint fuzzing, authenticated multi-user checks, container image scanning, public-network deployment, and sustained denial-of-service testing remain outside the completed scope.
