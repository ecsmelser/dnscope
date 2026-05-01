# DNScope

DNScope is a lightweight security monitoring project for tracking domains, running Nuclei scans, storing scan history, and reviewing how findings change over time.

The goal is to move beyond one-time scanning. DNScope is designed to keep a historical record of scans so users can review what was found, when it was found, and whether findings are new, resolved, or still present.

## Project Vision

DNScope is focused on DNS and web-facing security monitoring.

Current focus:

- track monitored domains
- run Nuclei scans against domain URLs
- store each scan as a historical scan run
- store normalized scan findings
- review latest scan state
- compare the latest scan against the previous scan
- inspect findings in a dashboard

Future focus:

- scan DNS records for subdomain takeover risk
- provide mitigation guidance for findings
- support scheduled recurring scans
- auto-refresh the dashboard while scans are running

## Current Features

- FastAPI backend
- PostgreSQL persistence
- domain creation and tracking
- Nuclei scan execution
- historical scan runs
- normalized finding fields
- latest scan summary per domain
- scan-to-scan diffing
- failed scan status and error visibility
- dashboard summary endpoint
- static frontend dashboard
- scan finding search and severity filters
- expandable raw evidence for findings

## Tech Stack

Backend:

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Docker Compose
- Nuclei

Frontend:

- HTML
- CSS
- JavaScript
- FastAPI JSON API

## Project Structure

```text
dnscope/
  backend/
    app/
      main.py
      routes.py
      models.py
      schemas.py
      db.py
      services/
        nuclei_runner.py
    requirements.txt
  frontend/
    index.html
    styles.css
    app.js
  docker-compose.yml
  .env.example


Requirements
Install these before running DNScope:

Python 3.12+
Docker Desktop
Nuclei
Git
Nuclei must be available from your terminal. You can test that with:

nuclei -version
Environment Variables
Create a .env file in the project root.

Example:

DATABASE_URL=postgresql://dnsuser:dnspass@localhost:5432/dnscope
CLOUDFLARE_API_TOKEN=replace_me
NUCLEI_PATH=nuclei
NUCLEI_TIMEOUT_SECONDS=120
DNSCOPE_ENV=local
Notes:

DATABASE_URL points the backend to Postgres.
NUCLEI_PATH=nuclei uses the Nuclei executable from your system path.
NUCLEI_TIMEOUT_SECONDS controls how long a scan can run before timing out.
CLOUDFLARE_API_TOKEN is reserved for future DNS/provider integration.
Start PostgreSQL
From the project root:

docker compose up -d
This starts a local Postgres database using docker-compose.yml.

To reset the local database during development:

docker compose down -v
docker compose up -d
Warning: docker compose down -v deletes local database data.

Run the Backend
From the project root:

cd backend
Create and activate a virtual environment if needed:

python -m venv .venv
.venv\Scripts\Activate.ps1
Install dependencies:

pip install -r requirements.txt
Run FastAPI:

uvicorn app.main:app --reload
The API will be available at:

http://127.0.0.1:8000
Swagger docs:

http://127.0.0.1:8000/docs
Open the Dashboard
Open this file in your browser:

frontend/index.html
The dashboard expects the backend to be running at:

http://127.0.0.1:8000
Demo Flow
A basic DNScope demo:

Start Postgres.
Start FastAPI.
Open the dashboard.
Add a domain.
Run a scan.
Review the latest scan summary.
Open scan findings.
Filter findings by severity or search text.
Run another scan.
Review scan history and scan diff.
Example flow through the API:

POST /domains
POST /scan/domain/{domain_id}
GET /domains/{domain_id}/latest-scan
GET /domains/{domain_id}/scan-runs
GET /domains/{domain_id}/scan-diff
GET /scan-runs/{scan_run_id}
GET /dashboard/summary
Important API Endpoints
Domain endpoints:

GET /domains
POST /domains
GET /domains/{domain_id}
Scan endpoints:

POST /scan/domain/{domain_id}
GET /scan-runs
GET /scan-runs/{scan_run_id}
GET /domains/{domain_id}/scan-runs
GET /domains/{domain_id}/latest-scan
GET /domains/{domain_id}/scan-diff
Finding endpoints:

GET /scan-results
Dashboard endpoints:

GET /dashboard/summary
Utility endpoints:

GET /health
POST /seed
Data Model Overview
DNScope currently stores:

Domain
a monitored domain, such as example.com
DNSRecord
reserved for DNS record tracking and future takeover detection
ScanRun
one scan event against a domain URL
ScanResult
one finding produced by a scan run
The most important relationship today is:

Domain
  -> ScanRun
       -> ScanResult
This allows DNScope to track scan history over time.

Scan Diff Logic
DNScope compares the latest scan against the previous scan for a domain.

The diff groups findings into:

new findings
resolved findings
persisting findings
The current comparison key is based on:

template id + matched target
This is a simple first version that works well enough for early monitoring behavior.