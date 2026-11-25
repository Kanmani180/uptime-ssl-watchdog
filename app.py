"""Website Uptime & SSL Certificate Watchdog.

A FastAPI app that checks a list of URLs in a background thread and serves
the results to a dark-mode dashboard (templates/index.html).
"""

from __future__ import annotations

import http
import json
import math
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3
from cryptography import x509
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------
# Configuration (override with environment variables)
# --------------------------------------------------------------------------
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "10"))      # seconds between checks
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8"))   # seconds per request
SSL_WARN_DAYS = int(os.getenv("SSL_WARN_DAYS", "30"))        # warn below this many days
SSL_CACHE_TTL = int(os.getenv("SSL_CACHE_TTL", "300"))       # re-check certs every N seconds
DATA_FILE = Path(os.getenv("WATCHDOG_DATA", "data/urls.json"))

DEFAULT_URLS = [
    "https://github.com",
    "https://google.com",
    "https://expired.badssl.com",
]
if os.getenv("WATCHDOG_URLS"):
    DEFAULT_URLS = [u.strip() for u in os.getenv("WATCHDOG_URLS", "").split(",") if u.strip()]

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# --------------------------------------------------------------------------
# Shared state
# --------------------------------------------------------------------------
lock = threading.RLock()
urls: list[str] = []
results: dict[str, dict] = {}
ssl_cache: dict[tuple[str, int], tuple[float, dict]] = {}
executor = ThreadPoolExecutor(max_workers=16)
stop_event = threading.Event()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# URL persistence & validation
# --------------------------------------------------------------------------
def normalize_url(raw: str) -> str:
    """Trim, add https:// if missing, and validate. Raises ValueError."""
    value = (raw or "").strip()
    if not value:
        raise ValueError("Enter a URL, for example https://example.com")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only valid http:// or https:// URLs are supported")
    return value.rstrip("/") if parsed.path in ("", "/") and not parsed.query else value


def load_urls() -> list[str]:
    if DATA_FILE.exists():
        try:
            saved = json.loads(DATA_FILE.read_text())
            if isinstance(saved, list) and saved:
                return [normalize_url(u) for u in saved]
        except (ValueError, OSError):
            pass
    return list(DEFAULT_URLS)


def save_urls() -> None:
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_FILE.write_text(json.dumps(urls, indent=2))
    except OSError:
        pass  # persistence is best-effort


# --------------------------------------------------------------------------
# SSL certificate check
# --------------------------------------------------------------------------
def _peer_der(host: str, port: int, verify: bool) -> bytes:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _expiry(der: bytes) -> datetime:
    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:  # older cryptography releases
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_after


def check_ssl(host: str, port: int) -> dict:
    """Return {state, expires_at, days_remaining, error}.

    state: valid | expiring | expired | invalid | unknown
    """
    key = (host, port)
    now = time.monotonic()
    with lock:
        cached = ssl_cache.get(key)
        if cached and now - cached[0] < SSL_CACHE_TTL:
            return _with_fresh_days(cached[1])

    result = {"state": "unknown", "expires_at": None, "days_remaining": None, "error": None}
    try:
        der = _peer_der(host, port, verify=True)
        result["expires_at"] = _expiry(der).isoformat()
        result["state"] = "valid"
    except ssl.SSLCertVerificationError as exc:
        result["state"] = "invalid"
        result["error"] = getattr(exc, "verify_message", None) or str(exc)
        try:  # fetch the cert anyway so we can still show its expiry date
            result["expires_at"] = _expiry(_peer_der(host, port, verify=False)).isoformat()
        except Exception:
            pass
    except (ssl.SSLError, OSError) as exc:
        result["error"] = str(exc) or exc.__class__.__name__
    except Exception as exc:  # parsing problems, etc.
        result["error"] = str(exc) or exc.__class__.__name__

    result = _with_fresh_days(result)
    with lock:
        ssl_cache[key] = (now, result)
    return result


def _with_fresh_days(result: dict) -> dict:
    """Recompute days remaining and state from the expiry date (cache-safe)."""
    out = dict(result)
    if out.get("expires_at"):
        expires = datetime.fromisoformat(out["expires_at"])
        days = math.floor((expires - utc_now()).total_seconds() / 86400)
        out["days_remaining"] = days
        if days < 0:
            out["state"] = "expired"
        elif out["state"] == "valid" and days < SSL_WARN_DAYS:
            out["state"] = "expiring"
    return out


# --------------------------------------------------------------------------
# HTTP check
# --------------------------------------------------------------------------
def check_url(url: str) -> dict:
    parsed = urlparse(url)
    result = {
        "url": url,
        "state": "DOWN",
        "status_code": None,
        "status_text": "Connection Error",
        "latency_ms": None,
        "ssl": None,
        "checked_at": None,
    }

    started = time.perf_counter()
    try:
        # verify=False so a bad certificate doesn't hide the HTTP result;
        # certificate problems are reported separately by check_ssl().
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            stream=True,
            headers={"User-Agent": "UptimeWatchdog/1.0"},
        )
        result["latency_ms"] = round((time.perf_counter() - started) * 1000)
        resp.close()
        code = resp.status_code
        result["status_code"] = code
        try:
            result["status_text"] = f"{code} {http.HTTPStatus(code).phrase}"
        except ValueError:
            result["status_text"] = str(code)
        http_ok = code < 400
    except requests.exceptions.Timeout:
        result["status_text"] = "Timeout"
        http_ok = False
    except requests.exceptions.RequestException:
        result["status_text"] = "Connection Error"
        http_ok = False

    if parsed.scheme == "https":
        result["ssl"] = check_ssl(parsed.hostname, parsed.port or 443)

    ssl_info = result["ssl"]
    if not http_ok:
        result["state"] = "DOWN"
    elif ssl_info and ssl_info["state"] != "valid":
        result["state"] = "SSL WARNING"
    else:
        result["state"] = "ONLINE"

    result["checked_at"] = utc_now().isoformat()
    return result


def refresh_one(url: str) -> None:
    res = check_url(url)
    with lock:
        if url in urls:  # it may have been removed while checking
            results[url] = res


def run_cycle() -> None:
    with lock:
        snapshot = list(urls)
    list(executor.map(refresh_one, snapshot))


def monitor_loop() -> None:
    while not stop_event.is_set():
        started = time.monotonic()
        try:
            run_cycle()
        except Exception as exc:  # never let the watchdog thread die
            print(f"[watchdog] cycle failed: {exc}")
        stop_event.wait(max(0.0, CHECK_INTERVAL - (time.monotonic() - started)))


# --------------------------------------------------------------------------
# FastAPI app
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_: FastAPI):
    with lock:
        urls[:] = load_urls()
    thread = threading.Thread(target=monitor_loop, name="watchdog", daemon=True)
    thread.start()
    yield
    stop_event.set()


app = FastAPI(title="Uptime & SSL Watchdog", lifespan=lifespan)


class UrlIn(BaseModel):
    url: str


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/status")
def api_status():
    with lock:
        sites = []
        for url in urls:
            sites.append(results.get(url) or {"url": url, "state": "PENDING"})
    summary = {
        "total": len(sites),
        "healthy": sum(s["state"] == "ONLINE" for s in sites),
        "ssl_warnings": sum(s["state"] == "SSL WARNING" for s in sites),
        "down": sum(s["state"] == "DOWN" for s in sites),
        "pending": sum(s["state"] == "PENDING" for s in sites),
    }
    return {
        "generated_at": utc_now().isoformat(),
        "check_interval": CHECK_INTERVAL,
        "ssl_warn_days": SSL_WARN_DAYS,
        "summary": summary,
        "sites": sites,
    }


@app.post("/api/urls", status_code=201)
def api_add_url(body: UrlIn):
    try:
        url = normalize_url(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with lock:
        if url in urls:
            raise HTTPException(status_code=409, detail=f"{url} is already monitored")
        urls.append(url)
        save_urls()
    executor.submit(refresh_one, url)  # first result shows up within seconds
    return {"url": url}


@app.delete("/api/urls")
def api_remove_url(url: str):
    with lock:
        if url not in urls:
            raise HTTPException(status_code=404, detail=f"{url} is not monitored")
        urls.remove(url)
        results.pop(url, None)
        save_urls()
    return {"removed": url}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
    )
