# Sentinel Scan

Scan IoCs and recursively inspect a folder chosen on your computer with ClamAV.

## Choose your frontend

Use either a web browser or the Electron desktop app. Both connect to the same
local services. Sign in with the same account to see your reports and quarantine
records in either frontend. Start the services:

```sh
docker compose up --build -d --wait --wait-timeout 300
```

From the project root, run `npm start` for a prompt offering **Web browser** or
**Electron app**. Or launch your preferred frontend directly:

```sh
# Web browser (also available directly at http://127.0.0.1:5173)
npm run start:web

# Electron: install once, then launch
npm ci --prefix desktop
npm run start:electron
```

The web frontend includes a **Launch desktop app** button on both the sign-in screen
and the workspace. On Linux, register its launch link once on the computer running
the browser (after installing desktop dependencies):

```sh
npm ci --prefix desktop
npm run register:desktop
```

The button opens `sentinel-scan://open`; the browser may ask to open the desktop app.
The handler always launches this checkout's Electron app and ignores incoming URL
parameters. It does not transfer web sessions or credentials. The button includes
setup instructions and a direct-command fallback, and is hidden inside Electron.
Registration creates a user-level Linux desktop entry and MIME association. Re-run
registration if you move this checkout. On Windows, starting Electron once registers
the handler. macOS source checkouts use `npm run start:electron`; browser links there
require a packaged application with URL-scheme metadata, as described in the
[Electron deep-link guide](https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app).

The Electron window uses the same frontend served at `http://127.0.0.1:5173`.
Docker must be running; the launcher reports how to start the services if they
are unavailable. Closing the window leaves the backend running. On macOS, use
**Quit** to end the desktop process. The browser and desktop app can also be open
at the same time. Electron requires a graphical desktop; installation downloads
the Electron runtime. Node.js 22 or newer is recommended for the launcher.

For a development frontend on another local port, set `SENTINEL_FRONTEND_URL`
when launching, for example:

```sh
SENTINEL_FRONTEND_URL=http://127.0.0.1:5174 npm run start:electron
```

Only local HTTP origins are accepted. The desktop renderer has Node integration
disabled, context isolation and sandboxing enabled, and no filesystem bridge.
It blocks navigation to other origins and unexpected windows, following the
[Electron security guidance](https://www.electronjs.org/docs/latest/tutorial/security).
Folder selection still uploads files to the backend; choosing Electron does not
grant permission to move originals selected through the folder picker.

Desktop checks:

```sh
npm run test:desktop
node --check desktop/main.cjs
node --check scripts/launch.mjs
```

## Accounts and private resources

Open the frontend and choose **Create an account**. Usernames are case-insensitive;
passwords must be 12–128 characters. Sign in, scan, and use **Sign out** when done.
Browser and Electron sessions are separate; the same account has the same history
in both. There are no default credentials. New accounts are ordinary users; an explicit
host-side promotion enables the first administrator.

All scan APIs require an authenticated session. Jobs (including upload/cancel),
reports, statistics, scan caches, and quarantine metadata are restricted to their
owner for ordinary users. Administrators can access every account's resources.
Another account's job returns 404 for ordinary users. Health endpoints remain public.

Passwords use salted scrypt (N=16384, r=8, p=5), following an
[OWASP-listed configuration](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Sessions expire after 12 hours, use HttpOnly/SameSite=Strict cookies, and are revoked
on sign-out. Session tokens are hashed in SQLite. Mutations require a CSRF token
and `X-Sentinel-Request: 1`; foreign Origin and non-loopback Host values are rejected.
API responses use `Cache-Control: no-store`. Login and registration attempts are
limited to ten per fifteen minutes per client; login also limits each username.
This local app accepts localhost, 127.0.0.1 and ::1. HTTPS cookies are Secure when
accessed directly through HTTPS; a remote TLS proxy requires explicit deployment
configuration and is outside the current loopback setup.

The existing database is migrated automatically without deleting scan or quarantine
records. **Historical records without an owner stay preserved but are hidden from
ordinary accounts.** No first registrant can claim other people's historical data. An explicitly promoted
administrator can inspect it.
There is currently no self-service password recovery or resource reassignment
interface. Keep your credentials and the persistent data volume safe.

API clients must first POST JSON credentials to `/api/v1/auth/register` or `/login`
under `/api/v1/auth`, with `X-Sentinel-Request: 1`, retain the session cookie, and send
`X-CSRF-Token` from the response for mutations. GET `/api/v1/auth/me` restores the
username/CSRF token; POST `/api/v1/auth/logout` revokes that session.

## Admin portal

Create the administrator's account through the frontend, then explicitly promote it
from the project directory. For the configured first administrator:

```sh
docker compose exec backend /app/lib/bin/python -m app.manage_admin promote clamscan-admin
```

This command never creates a password or promotes the first registrant automatically.
It promotes only the named existing account and revokes its sessions. Sign in again
and select **Admin portal** in the sidebar. Usernames are case-insensitive.

Administrators see global reports, statistics, quarantine metadata, and every scan
job, including historical records without an owner. Owner labels distinguish records
from different accounts. The portal lists accounts, shows job manifests/results,
exports job details, and can cancel folder uploads. Completing another user's upload
preserves the original owner's scan and quarantine records. Quarantine payloads retain
the existing isolation behavior and have no browser preview or download endpoint.

Administrators can change other users’ passwords, grant/remove admin roles, and revoke
account sessions. In **Admin portal → Accounts**, choose **Change password**, enter
and confirm a 12–128 character password, then choose **Save password**. Password
changes use a fresh salt, revoke all target sessions, and appear in the administrator
action log; password values are never returned or logged. The administrator cannot
change their own password through this control. Role changes
revoke the target's sessions, and roles are checked against the database on every
request. The last administrator cannot be demoted. Role changes and session
revocations appear in the portal's administrator action log. Password hashes and
session secrets are never included in account listings. Jobs remain in-memory and
are lost on backend restart; persisted scan/quarantine records survive restart.

## Choose a folder to scan

Start the services:

```sh
docker compose up --build -d --wait --wait-timeout 300
```

Open `http://localhost:5173`, sign in, select **Folder scan**, then **Choose folder**.
Choose a folder in the system picker and click **Start recursive scan**. Files in
nested folders are included automatically. The browser sends files to the backend
one at a time for ClamAV inspection; reports store hashes, never file contents.
Relative paths are included in live results and the JSON export.

The selected folder may contain up to 10,000 files. Files larger than 25 MB are
reported as skipped without uploading their contents. Empty directories are not
included by the browser picker. An interrupted upload leaves partial results and
marks the job failed; reselect the folder and retry. Abandoned uploads expire after
10 minutes of inactivity when a new selected-folder scan is requested. ClamAV must
be configured for folder scanning.


## Quarantine

Folder scans automatically isolate files with a **malicious** verdict. Clean,
suspicious, unknown, skipped, and failed scans are not quarantined. Quarantine is
stored in `QUARANTINE_DIR`, which defaults to a directory beside the database;
Compose fixes it at `/app/data/quarantine` in the persistent `app-data` volume.
Payloads use generated `.bin`
names with owner-only permissions and no executable permission. The **Quarantine**
view lists original paths, hashes, sizes, timestamps, and the action taken. Payloads
are not exposed by an API or download link. Restore and deletion controls are not
yet implemented.

**Browser-selected folders:** the backend quarantines the uploaded malicious copy.
The browser picker cannot move or delete the original file on your computer; it
remains in place. Scan results explicitly identify this as a stored copy.

Quarantine stores malicious file contents, unlike scan reports, which store hashes.
It persists across container restarts. Failed isolation is shown
separately from the malware verdict so a malicious detection remains visible.

## Run and stop the services

Create `.env` from `.env.example` to configure optional reputation-provider keys.
After sign-in, a reminder lists missing VirusTotal, AlienVault OTX and MalwareBazaar
keys. Administrators can expand setup instructions; ordinary users are prompted to
contact their administrator. The reminder stays visible while any key is missing
and disappears once all three are configured. It does not prevent ClamAV scanning.
Only configuration-presence booleans are sent to the frontend, never API key values.
After editing `.env`, run `docker compose up -d --force-recreate backend frontend`
and refresh the page. Finish active scans first because recreation interrupts jobs.
Key presence does not guarantee the key is valid or that the provider is reachable.
ClamAV must finish downloading signatures before scanning; inspect its logs with
`docker compose logs clamd`.

The frontend and backend run as non-root users. The backend root filesystem is
read-only, with writable storage limited to its data volume and temporary files.
Health checks gate startup. Only the frontend is exposed, on `127.0.0.1:5173`;
backend and ClamAV ports remain internal. Provider API keys are passed at runtime.

```sh
docker compose ps
docker compose logs --tail 100
docker compose down
```

Stopping the stack preserves the `app-data` and `clam-db` named volumes, including
scan reports, signatures, and quarantine payloads.

## Host development

Run the backend and configure a reachable ClamAV instance. To expose the Compose ClamAV service on loopback:

```sh
docker compose -f docker-compose.yml -f deploy/clamd/local-preview.yml up -d clamd
cd backend
CLAMD_HOST=127.0.0.1 CLAMD_PORT=3310 uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

A completed job can still include skipped files, errors, or unknown verdicts;
completion does not imply the folder is clean.

Only one selected-folder job runs at a time per backend process. Jobs and their path lists
currently live in memory and disappear on restart; download results to keep them.
The default deployment binds the frontend to localhost because authentication
is not yet implemented. Folder scans require ClamAV configuration; unavailable scanners produce
unknown verdicts. Reputation enrichment sends hashes to configured providers,
never file contents. A clean ClamAV result skips reputation enrichment.

## Folder API

- `POST /api/v1/selected-folder-scan` with `{"files":[{"path":"chosen/file.txt","size":4}]}`: starts a selected-folder job.
- `PUT /api/v1/selected-folder-scan/{job_id}/files/{index}`: sends raw file bytes in manifest order; the last file completes the job. Send an empty body for oversized files.
- `DELETE /api/v1/selected-folder-scan/{job_id}`: marks an interrupted selected-folder job failed.
- `GET /api/v1/quarantine?page=1&page_size=20`: persisted quarantine metadata only.
- `GET /api/v1/folder-config`: scanner configuration and upload limits.
- `GET /api/v1/scan/{job_id}`: progress counters, status and per-file results.

## Checks

```sh
cd backend
uv run pytest
uv run ruff check .
uv run ruff format --check .
cd ../frontend
npm run build
```

To verify recursive selected-folder uploads and real ClamAV quarantine inside the running backend container
(using isolated temporary fixtures and a temporary database):

```sh
docker compose exec -T backend /app/lib/bin/python < deploy/verify_container.py
```
