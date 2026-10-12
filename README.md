# DangleScan — Subdomain Takeover Scanner

Scan domains for dangling DNS and takeover evidence, keep scan history, and automatically capture each reachable webpage in Finding Details.

## What is included

- `main.py` — FastAPI backend, scanning, enumeration and detection rules
- `database.py` — SQLite/PostgreSQL database setup and history functions
- `index.html` — scanner interface
- `detail.html` — full result evidence page
- `history.html` — stored scan history page
- `requirements.txt` — Python packages
- `migrate_sqlite_to_postgres.py` — optional future migration utility
- `tests/` — automated tests for detection and database behaviour
- `screenshots.py` — automatic Chromium webpage captures
- `Start_DangleScan.command` — macOS startup launcher

## Database behaviour

No scan-history database is included in this release. This is intentional.
Historical scan data can contain internal asset information and should not be
shared unless it has been approved.

The first time the backend starts, it automatically creates `danglescan.db` in
this folder. It also creates the required `scans` and `scan_results` tables.
No manual database installation is needed for a local demonstration.

The SQLite database belongs to the backend. Port 8000 is the backend address;
it is not the database port.

## Run on macOS or Linux

Open Terminal in this folder and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
uvicorn main:app --host 127.0.0.1 --port 8000
```

Keep that Terminal open. Open a second Terminal in the same folder and run:

```bash
source .venv/bin/activate
python -m http.server 3000 --bind 127.0.0.1
```

Open the scanner:

```text
http://127.0.0.1:3000/index.html?api=http%3A%2F%2F127.0.0.1%3A8000
```

Useful pages:

- Scanner: `http://127.0.0.1:3000/index.html?api=http%3A%2F%2F127.0.0.1%3A8000`
- Scan History: `http://127.0.0.1:3000/history.html?api=http%3A%2F%2F127.0.0.1%3A8000`
- Backend health: `http://127.0.0.1:8000/health`
- Read-only raw database view: `http://127.0.0.1:8000/database`

Use `http://`, not `https://`, for these local addresses.

## Optional enumeration tools

DangleScan can use Subfinder and Amass when they are installed. It also uses
the configured passive web sources. The scanner still runs if Subfinder or
Amass is unavailable, but discovery coverage may be lower.

## Optional AI analysis

The deterministic rule engine works without an API key. To enable the optional
analyst summary, set `OPENAI_API_KEY` before starting the backend. Do not place
the real key in this folder or commit it to source control.

## Run the automated checks

```bash
source .venv/bin/activate
python -m unittest discover -s tests -v
```

The test suite covers DNS rules, persistence, and automatic webpage screenshots.

## Moving existing SQLite history

Only do this when the scan history has been approved for sharing.

1. Stop the DangleScan backend completely.
2. Copy the single `danglescan.db` file into this folder.
3. Do not copy `danglescan.db-wal` or `danglescan.db-shm` while the backend is
   running.
4. Start the backend and open Scan History.

For a clean demonstration, do not copy any database. A new empty database is
created automatically.

## PostgreSQL for production

SQLite is suitable for a local demonstration. PostgreSQL is recommended for a
shared production deployment because it supports concurrent workers, central
backups, access control and recovery.

The application can use PostgreSQL through `DATABASE_URL`:

```bash
export DATABASE_URL="postgresql+psycopg://username:password@hostname:5432/danglescan"
uvicorn main:app --host 127.0.0.1 --port 8000
```

Use managed credentials and TLS in production. Do not store passwords in the
source files.

## Important release note

`video.pitchforkmedia.com` is classified as **Configuration Issue / Info** when
the AWS S3 bucket endpoint exists but the custom hostname has an HTTPS
certificate problem or the regional endpoint returns an error such as HTTP 403.
The result explains the configuration problem separately from takeover risk.


## Automatic webpage screenshots

Every new subdomain result includes screenshot evidence. A separate headless Chromium
browser visits HTTPS, then falls back to HTTP if navigation fails, and captures a
1440 × 900 viewport. The image appears directly below Finding on the details page
and can be opened at full size. There is no manual screenshot button and Flameshot
is no longer required. Browser capture uses Playwright: https://playwright.dev/python/docs/screenshots.

Install the Python requirements and run `python -m playwright install chromium`
in the same environment/account as the backend. On Linux servers, use Playwright's
OS dependency installation instructions if Chromium needs system libraries.

Two captures run concurrently. Each has a 35-second timeout once a slot is available;
capture time adds to scan duration. Each capture uses a fresh browser without saved
sessions, downloads, or granted permissions. TLS verification remains enabled.
Private/local addresses are excluded from browser requests. These checks are not
a substitute for network egress isolation when deploying an untrusted-target scanner.

Screenshots are saved under `data/screenshots/`; override this with
`DANGLESCAN_SCREENSHOT_DIR`. Keep this folder with database backups because scan
history stores image references. Images remain until explicitly removed; plan disk
space accordingly. Do not expose the development servers publicly.

Unresolvable domains, non-web services, browser failures, and unreachable pages show
an explanatory status instead of a misleading blank image. Older findings need a
new scan to gain screenshots. HTTP error pages are captured when a browser can render
them. Screenshots do not change the DNS/HTTP risk verdict.

### Starting on macOS

Codex's shell sandbox may prevent Chromium from starting (a macOS Mach port
permission error). Run the included `Start_DangleScan.command` from your normal
Terminal to start the backend and frontend outside that sandbox. This does not
require disabling Chromium's sandbox or TLS checks. Stop an existing backend on
port 8000 first. The launcher creates `.venv` and installs dependencies when needed.
