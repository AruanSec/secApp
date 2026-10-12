# Sentinel Scan

Scan IoCs and recursively inspect a folder chosen on your computer with ClamAV.

## Deploy on a new device

This is a source-based installation: Docker runs the backend, web frontend and
ClamAV; Electron runs on the host computer. There is currently no packaged Windows
installer, macOS application bundle or Linux application package. Use a browser
for the simplest installation, or install Node.js to use the frontend chooser and
Electron. The app is configured for use on the same computer as Docker, at
[http://127.0.0.1:5173](http://127.0.0.1:5173).

### 1. Install prerequisites

| Device | Docker setup | Terminal for these instructions |
| --- | --- | --- |
| Windows | Install [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/), enable its WSL 2 backend and use **Linux containers**. Follow Docker's supported Windows and virtualization requirements. Start Docker Desktop. | Native Windows PowerShell. Install Node.js for Windows and run Electron here, rather than installing Linux Electron dependencies inside WSL. |
| macOS | Install [Docker Desktop for Mac](https://docs.docker.com/desktop/setup/install/mac-install/), choosing the installer for Apple silicon or Intel. Start Docker Desktop. | Terminal. |
| Linux | Install [Docker Engine](https://docs.docker.com/engine/install/) and its Compose plugin, or Docker Desktop. Ensure the Docker service is running and your account can run Docker commands. | A terminal in your graphical desktop session if using Electron. |

Use Docker Compose **2.24.0 or newer**; the Compose file uses the optional
`env_file.required` setting introduced in that version.
[Docker's environment-file documentation](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/)
explains this requirement. Use `docker compose`, not the older `docker-compose` command.

For the launcher or Electron, install [Node.js](https://nodejs.org/en/download)
22 or newer, including npm. Node.js and Python are not needed on the host when you
only open the Docker-served frontend in a browser. Internet access is needed for
container images, npm packages, ClamAV signatures and configured reputation providers.
Use a Docker-supported machine with sufficient memory for ClamAV; its initial
signature download and startup may take several minutes.

Verify your installation:

```sh
docker version
docker compose version
# Only required for the chooser or Electron:
node --version
npm --version
```

On PowerShell, use `npm.cmd` instead of `npm` if execution policy blocks `npm.ps1`;
there is no need to weaken the execution policy.

### 2. Copy the source to the device

Clone your repository if you have published it, or transfer a source archive from
the existing device. To export the committed source, run this from its project folder:

```sh
git archive --format=zip --prefix=secApp/ --output=../secApp-source.zip HEAD
```

The archive includes only committed files. Commit any changes you want to transfer
first. Copy `secApp-source.zip` to the new device and extract it. Do not copy
`node_modules`, `.venv`, `dist`, or the previous device's desktop-link registration;
install native Electron dependencies again on the destination.

Open a terminal in the extracted `secApp` folder, which contains `docker-compose.yml`.
For example, replace the sample path with your actual location:

**Windows PowerShell**

```powershell
Set-Location "C:\path\to\secApp"
if (!(Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

**macOS / Linux**

```sh
cd /path/to/secApp
# Create the configuration file only if it is not already present:
test -f .env || cp .env.example .env
```

On macOS/Linux, open `.env` in your preferred text editor. Set any reputation-provider
keys you want to use:

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key
ALIENVAULT_API_KEY=your_otx_key
ABUSECH_API_KEY=your_malwarebazaar_key
```

Replace the sample values with real keys, or leave a value empty to skip that provider.
The app reminds signed-in users about missing keys. Do not commit `.env`. Keep the
container paths and ClamAV settings from `.env.example`; Compose supplies the internal
service addresses. Leave `APP_UID` and `APP_GID` unset on a fresh installation unless
you specifically need custom container ownership.

### 3. Build and start the app

Run the following from the project folder on any of the three operating systems:

```sh
docker compose up --build -d --wait --wait-timeout 600
docker compose ps
```

Wait for **backend**, **frontend** and **clamd** to be healthy. If the first startup
exceeds the wait timeout, inspect `docker compose logs --tail 100 clamd`, let signature
initialization finish, and retry `docker compose up -d --wait --wait-timeout 600`.

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) in the browser on **that same device**.
Use `http`, not `https`. No host-folder mapping or native ClamAV installation is
needed; the folder picker uploads selected files to the containerized scanner.

### 4. Create accounts and enable an administrator

Choose **Create an account**, set a username and a 12–128 character password, then
sign in. There are no default credentials. To make that account an administrator,
replace `YOUR_USERNAME` below with the username you just created:

```sh
docker compose exec backend /app/lib/bin/python -m app.manage_admin promote YOUR_USERNAME
```

Sign in again after promotion, then select **Admin portal → Accounts**. Administrators
can access all accounts' records, change other users' passwords and roles, and revoke
sessions. Ordinary users see their own resources. Create additional accounts through
the same registration screen. See [Accounts and private resources](#accounts-and-private-resources)
and [Admin portal](#admin-portal) for details.

### 5. Choose browser or Electron

**Browser only:** open the URL above; no host npm installation step is needed.

**Windows PowerShell — chooser or desktop**

```powershell
npm.cmd ci --prefix desktop
npm.cmd start
# Or launch Electron directly:
npm.cmd run start:electron
```

**macOS / Linux — chooser or desktop**

```sh
npm ci --prefix desktop
npm start
# Or launch Electron directly:
npm run start:electron
```

Choose **Web browser** or **Electron app** when prompted by `npm start`. Keep Docker
running for either frontend. Sign in separately in each frontend using the same
account; both access this device's backend and persistent records.

The web page also has a **Launch desktop app** button:

| Device | One-time launch-link setup |
| --- | --- |
| Linux | After installing desktop dependencies, run `npm run register:desktop` in the graphical session on the browser's computer. Accept the browser's open-app prompt when you click the button. Re-register after moving the source folder. |
| Windows | Run `npm.cmd run start:electron` once to register the launch link. Then use the browser button. |
| macOS | This source checkout supports `npm run start:electron`. The browser button requires a packaged application with URL-scheme metadata, which this repository does not currently provide. |

A Linux desktop session needs `xdg-mime` and a working default URL opener for
registration/launch. Use the direct Electron command if the browser does not recognize
the link. Native desktop dependencies must be installed for the destination device's
OS/CPU; do not reuse another device's `node_modules`.

### 6. Verify, stop and update

Sign in, check the API-key reminder, and run **Folder scan → Choose folder** on a
small folder of harmless files. Confirm that the job finishes and its report appears.
This checks the app workflow; a finished job or an unknown verdict is not proof that
all files are safe. Browser and desktop folder selection use the same scanning API.

```sh
# Check service state and recent logs:
docker compose ps
docker compose logs --tail 100
# Stop containers while retaining accounts, reports and quarantine:
docker compose down
# Start again later:
docker compose up -d --wait --wait-timeout 600
# After updating source files:
docker compose up --build -d --wait --wait-timeout 600
# After changing provider keys in .env:
docker compose up -d --force-recreate --wait --wait-timeout 600 backend frontend
```

Finish scans before an update or recreation: live jobs are held in memory and are
lost when the backend restarts. When desktop dependencies change, run
`npm ci --prefix desktop` again (`npm.cmd ci --prefix desktop` on PowerShell).

**Source transfer is not data migration.** Accounts, password hashes, reports and
quarantine contents live in the `app-data` Docker volume; signatures live in `clam-db`.
These volumes and `.env` are not included in the Git source archive. A fresh device
starts with a new database and no accounts. If you need existing records, stop scans
and back up/restore the volumes separately using
[Docker's volume backup and restore guidance](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes).
Keep `.env` and data backups private; quarantine backups contain malicious payloads.
`docker compose down` preserves volumes; **`docker compose down -v` deletes them**.
Changing the project/folder name on an existing device can also select different
Compose volumes, making existing data appear absent.

### Troubleshooting a new device

- **Docker daemon unavailable:** start Docker Desktop on Windows/macOS, or the Docker
  service on Linux. Windows must use Linux containers. Check `docker version` before
  trying the app commands again.
- **Frontend unreachable:** check `docker compose ps` and logs. Open exactly
  `http://127.0.0.1:5173` on the computer running Docker; another device's localhost
  points to that device. This deployment does not expose a LAN/public endpoint, and
  backend authentication accepts loopback Host values.
- **ClamAV unhealthy or startup timeout:** inspect its logs for signature-download,
  network or memory problems. Give initialization time to finish before retrying.
- **Unsupported image architecture:** inspect `docker compose pull clamd` and the
  [official ClamAV image documentation](https://docs.clamav.net/manual/Installing/Docker.html).
  Check image support for your CPU, especially Apple silicon or Windows ARM; do not
  assume an x86-only image can run natively. These instructions have been checked
  against the code and official setup docs, but Windows/macOS deployments have not
  been tested here.
- **Port 5173 already used:** stop the conflicting local service. Changing the port
  also requires updating the launcher URL; see [Choose your frontend](#choose-your-frontend).
- **Electron does not start:** use `npm ci --prefix desktop` on the destination OS,
  run the direct launch command in a terminal, and inspect its error. Linux requires
  a graphical desktop and Electron's system libraries. Browser mode works without
  host Electron dependencies; do not disable Electron's sandbox to work around errors.
- **No Admin portal:** promote an existing account using step 4, then sign in again.
- **Keys still reported missing:** recreate backend/frontend after editing the project
  root `.env`, then refresh. Setting keys in a different device's environment does not
  configure this instance.


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

Windows PowerShell:

```powershell
$env:SENTINEL_FRONTEND_URL = "http://127.0.0.1:5174"
npm.cmd run start:electron
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

API clients must first POST JSON credentials to `/api/v1/auth/register` or
`/api/v1/auth/login`, with `X-Sentinel-Request: 1`, retain the session cookie, and send
`X-CSRF-Token` from the response for mutations. GET `/api/v1/auth/me` restores the
username/CSRF token; POST `/api/v1/auth/logout` revokes that session.

## Admin portal

Create the administrator's account through the frontend, then explicitly promote it
from the project directory. Replace `YOUR_USERNAME` with the account you created:

```sh
docker compose exec backend /app/lib/bin/python -m app.manage_admin promote YOUR_USERNAME
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

## Host development (optional; macOS/Linux shell examples)

This section is for development without the Dockerized backend. It requires a
local Python 3.12+ runtime and `uv`; these are not prerequisites for the Docker
deployment above.

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
The default deployment binds the frontend to localhost for local-device use.
Authentication and resource ownership are enforced by the backend. Folder scans require ClamAV configuration; unavailable scanners produce
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

For bounded API security probes using a temporary database and mocked scanner/provider
responses, run from the project root. This checks API controls; it does not perform a
real ClamAV malware scan or modify live account/scan data. The output can still report
known unremediated controls; see `security/OWASP-Top-10-2025.md`.

macOS/Linux:

```sh
docker compose exec -T backend /app/lib/bin/python < security/assess_api.py
```

Windows PowerShell:

```powershell
Get-Content -Raw .\security\assess_api.py | docker compose exec -T backend /app/lib/bin/python
```
