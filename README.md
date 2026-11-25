# Watchdog: Website Uptime & SSL Certificate Monitor

A small real-time monitoring app. A Python (FastAPI) backend checks your sites every 10 seconds in a background thread, and a dark-mode dashboard (plain HTML, CSS and JavaScript, no build step) refreshes itself every 5 seconds.

## Features

- Background checks of every monitored URL every 10 seconds, run in parallel
- Per URL: HTTP status (`200 OK`, `500 Internal Server Error`, `Timeout`, `Connection Error`), latency in ms, SSL/TLS expiry date and days remaining
- SSL warnings when a certificate has fewer than 30 days left, is expired, or fails validation
- Dashboard with KPI cards (Total Monitored, Healthy, SSL Warnings, Down), color-coded `ONLINE` / `SSL WARNING` / `DOWN` badges, and latency bars
- Add and remove URLs while it runs; the list is saved to `data/urls.json`
- Auto-refresh via `fetch()`, no page reloads

## Project structure

```
.
├── app.py              # FastAPI app, background monitor, API
├── requirements.txt
├── templates/
│   └── index.html      # Dashboard (HTML + CSS + JS)
├── .gitignore
└── README.md
```

## Setup

Requires Python 3.9 or newer.

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python app.py
```

Open <http://127.0.0.1:8000>.

You can also run it with uvicorn directly:

```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

> Run a single worker. Monitoring state is held in memory, so multiple workers would each run their own checks.

## Configuration

All settings are optional environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `WATCHDOG_URLS` | `https://github.com,https://google.com,https://expired.badssl.com` | Comma-separated starting URLs (used when no saved list exists) |
| `CHECK_INTERVAL` | `10` | Seconds between check cycles |
| `REQUEST_TIMEOUT` | `8` | Seconds before a request counts as `Timeout` |
| `SSL_WARN_DAYS` | `30` | Warn when a certificate has fewer days left |
| `SSL_CACHE_TTL` | `300` | Seconds to cache a certificate lookup per host |
| `WATCHDOG_DATA` | `data/urls.json` | Where the URL list is saved |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Bind address (`python app.py` only) |

Example:

```bash
WATCHDOG_URLS="https://example.com,https://status.example.org" CHECK_INTERVAL=15 python app.py
```

To reset to the default list, delete `data/urls.json`.

## How status is decided

| Badge | Condition |
|---|---|
| `DOWN` | Timeout, connection error, or HTTP status 400 or higher |
| `SSL WARNING` | Site responds, but the certificate is expired, invalid, unreadable, or has fewer than 30 days left |
| `ONLINE` | Site responds with status below 400 and the certificate is healthy (or the URL is plain `http://`) |
| `CHECKING` | Added, first result not in yet |

Notes:

- HTTP requests ignore certificate errors, so a bad certificate shows as `SSL WARNING` rather than hiding the HTTP result. `https://expired.badssl.com` is expected to show `SSL WARNING`.
- Certificates are looked up separately and cached for 5 minutes per host. Days remaining are recalculated on every check.
- Latency is the time to receive the response headers, including redirects.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/api/status` | Summary counts and per-site results |
| `POST` | `/api/urls` | Add a site. Body: `{"url": "https://example.com"}` |
| `DELETE` | `/api/urls?url=<url>` | Remove a site |

```bash
curl http://127.0.0.1:8000/api/status
curl -X POST http://127.0.0.1:8000/api/urls -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
curl -X DELETE "http://127.0.0.1:8000/api/urls?url=https://example.com"
```

## Troubleshooting

- **Everything shows `Connection Error`:** check that the machine has outbound internet access and that a proxy or firewall isn't blocking port 443.
- **A site shows `Timeout`:** raise `REQUEST_TIMEOUT`.
- **A healthy site returns 403 and shows `DOWN`:** some sites block automated requests. That is a status of 400 or higher, so it counts as down.
- **Port already in use:** run with `PORT=8080 python app.py`.

## Security note

The app has no authentication and makes outbound requests to any URL you add. Keep it bound to `127.0.0.1`, or put it behind authentication before exposing it to a network.
