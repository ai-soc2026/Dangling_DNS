# DangleScan — Subdomain Takeover Scanner

Scan thousands of domains for dangling DNS records and subdomain takeover vulnerabilities.
Input: Excel file (.xlsx) with domains. Output: real-time streaming results with optional Codex analysis and optional subdomain enumeration.

## Requirements
- Python 3.11+
- OpenAI API key for Codex analysis (optional)
- `amass` and/or `subfinder` for subdomain enumeration (optional)

## Setup

### 1. Configure Codex analysis (optional)
```bash
export OPENAI_API_KEY="your_api_key_here"
# Optional: override the default model
export OPENAI_MODEL="gpt-5.2"
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Start the backend
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open the frontend
```bash
# Just open index.html in your browser
# Or serve it from this folder:
python -m http.server 3000
# Then visit http://localhost:3000
```

### 5. Install enumeration tools (optional)
```bash
# macOS examples
brew install amass
brew install subfinder
```

## Scan history database

DangleScan supports both SQLite and PostgreSQL through SQLAlchemy.

- With no `DATABASE_URL`, it uses the local `danglescan.db` SQLite file.
- With a PostgreSQL `DATABASE_URL`, it creates and uses the same tables in PostgreSQL.

SQLite remains the zero-configuration local default. PostgreSQL is recommended
for a deployed, shared or multi-user environment.

Results are written progressively while a scan runs. If a scan is stopped, the
results completed before the stop remain available and the scan is marked
`stopped`.

History endpoints:

- `GET /history/scans` — list scans
- `GET /history/scans/{scan_id}` — read a scan summary
- `GET /history/scans/{scan_id}/results` — list and filter a scan's results
- `GET /history/search?q=...` — search results across all historical scans
- `GET /history/results/{result_id}` — read complete stored evidence
- `PATCH /history/results/{result_id}` — update remediation status, owner and comment
- `GET /database` — read-only JSON view of stored scans and results for demonstrations

Set `DANGLESCAN_DB_PATH` before starting the backend to store the database at a
different SQLite location.

### Use PostgreSQL

Configure the connection before starting the backend:

```bash
export DATABASE_URL="postgresql+psycopg://username:password@hostname:5432/danglescan"
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The application creates empty `scans` and `scan_results` tables automatically.
Do not put the real password in source code or commit it to Git.

### Copy existing SQLite history to PostgreSQL

First validate the source without changing PostgreSQL:

```bash
export POSTGRES_DATABASE_URL="postgresql+psycopg://username:password@hostname:5432/danglescan"
python migrate_sqlite_to_postgres.py --dry-run
```

Then copy the history into an empty PostgreSQL database:

```bash
python migrate_sqlite_to_postgres.py
```

After the row counts are verified, set `DATABASE_URL` to the same PostgreSQL URL
and start the application. Keep `danglescan.db` as a backup until the PostgreSQL
deployment has been validated.

## Excel Format
- Any .xlsx file works
- Put domains one per cell, any sheet, any column
- Examples of valid values: `example.com`, `api.example.com`, `staging.brand.io`
- Headers are ignored (non-domain text is skipped automatically)

## How it works

### Rule engine (always runs, zero cost)
- Checks DNS: A records, CNAME targets, NXDOMAIN
- Detects 20+ cloud provider takeover fingerprints in HTTP responses
- Identifies dangling CNAMEs to AWS S3, Azure, Heroku, GitHub Pages, Netlify, etc.

### AI layer (Codex via OpenAI API)
- Runs only on non-clean findings to save time
- Filters false positives with contextual reasoning
- Generates plain-English remediation briefs
- Identifies likely owning team (infra/marketing/dev)
- Toggle on/off in the UI

### Subdomain enumeration
- Toggle on/off in the UI
- Runs `subfinder -silent -d <domain>` when `subfinder` is installed
- Runs `amass enum -passive -d <domain>` when `amass` is installed
- Merges discovered subdomains with domains from the uploaded Excel file before scanning

### Severity scoring
- **Critical**: Confirmed takeover signature in HTTP body
- **High**: Dangling CNAME to cloud provider, NXDOMAIN
- **High**: Redirect to an unrelated external domain (unless it is the built-in Condé Nast Okta tenant or is allowlisted with `REDIRECT_DOMAIN_ALLOWLIST`)
- **Medium**: HTTP 404/410 on cloud-pointed domain
- **Clean**: Domain resolves and no issues found

## Performance
- 10 concurrent domain scans
- ~2-5 seconds per domain (with AI), ~0.5s (rules only)
- 100 domains ≈ 1-2 minutes
- 4000 domains ≈ 20-40 minutes (run overnight)

## Concorde with your Condé Nast setup
Point this at your domain list export. Schedule via cron:
```bash
# Run every 6 hours, save results
0 */6 * * * curl -s -X POST http://localhost:8000/scan \
  -F "file=@/path/to/domains.xlsx" \
  -F "use_ai=true" > /var/log/danglescan/$(date +\%Y\%m\%d_\%H\%M).jsonl
```
