# syntax=docker/dockerfile:1
# ============================================================================
#  ELMINYAWE Smart Solver API  —  Deplexo-ready edition
# ----------------------------------------------------------------------------
#  Engine: patchright + headed Chromium on Xvfb (the exact stack proven on
#  this platform by the working "turn" project). FlareSolverr /
#  undetected_chromedriver are GONE - they could not run under the
#  read-only rootfs / noexec volume constraints (chromedriver patching,
#  exec on /data, unmanaged stdio pipes).
#
#  ARCHITECTURE: one process, one app.
#    - Public API (gateway + smart response format) on ELMINYAWE_PORT=8191.
#    - Platform-injected PORT (e.g. 8080) is bound by the SAME process as
#      a compat alias -> a port-mismatch 502 is impossible by construction.
#    - The solving engine is in-process (private Chromium pipe, no port).
#
#  ENDPOINTS (unchanged):
#    GET  /         -> service info
#    GET  /health   -> engine status
#    GET  /solve    -> /solve?url=<target>&session=<opt>&maxTimeout=<opt>
#    POST /v1       -> FlareSolverr-compatible (cmd=request.get / request.post,
#                      request.createSession / request.destroySession)
#                      smart response: "result" first, HTML "solution" last
#
#  ENV CONFIG (all optional):
#    ELMINYAWE_PORT=8191       primary public API port
#    PORT=<platform port>      platform-injected compat port (alias)
#    ELMINYAWE_HEADLESS=false  false = headed on Xvfb (default, best stealth)
#    ELMINYAWE_BROWSER=chromium  chromium | chrome | msedge
#    ELMINYAWE_UA=...          force a User-Agent (optional)
#    MAX_CONCURRENT_SOLVES=2   simultaneous browser sessions (RAM guard)
#    LOG_LEVEL=info
# ============================================================================

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    HOST=0.0.0.0 \
    ELMINYAWE_PORT=8191 \
    LOG_LEVEL=info \
    MAX_CONCURRENT_SOLVES=2 \
    ELMINYAWE_HEADLESS=false \
    ELMINYAWE_BROWSER=chromium \
    ELMINYAWE_UA="" \
    LANG=en \
    TZ=UTC

# --- system: virtual display (headed stealth mode) + fonts + certs -----------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        xvfb \
        fonts-liberation \
        fonts-dejavu-core \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# --- engine driver (patchright) + API framework -------------------------------
RUN pip install --no-cache-dir patchright fastapi "uvicorn[standard]"

# --- browsers used by the engine (with all their OS dependencies) -------------
#  chromium = default channel (patchright full build, new headless capable)
#  chrome   = real Google Chrome (activate with ELMINYAWE_BROWSER=chrome)
RUN python -m patchright install --with-deps chromium \
 && python -m patchright install chrome

WORKDIR /app

# ============================================================================
#  EMBEDDED FILE 1/4 : /app/elminyawe_engine.py
#  Solving core (patchright). FlareSolverr /v1 compatible.
# ============================================================================
RUN cat > /app/elminyawe_engine.py <<'PYENGINE'
# ============================================================
#  ELMINYAWE Engine - Cloudflare-aware page solving core
#  Browser stack: patchright (proven on this platform - same
#  engine as the working "turn" project), headed on Xvfb.
#  API surface: FlareSolverr /v1 compatible (request.get/post,
#  sessions) so the ELMINYAWE gateway needs no logic changes.
# ============================================================
import os
import logging
import threading
import time
import uuid
from typing import Optional
from urllib.parse import urlsplit

from patchright.sync_api import sync_playwright

# ---------------- configuration ----------------

ENGINE_VERSION = "ELMINYAWE-Engine/1.0"
BROWSER_TYPE = (os.environ.get("ELMINYAWE_BROWSER") or "chromium").strip().lower()
HEADED = (os.environ.get("ELMINYAWE_HEADLESS") or "false").strip().lower() != "true"
MAX_CONCURRENT = max(1, int(os.environ.get("MAX_CONCURRENT_SOLVES", "2")))
USER_AGENT = (os.environ.get("ELMINYAWE_UA") or "").strip() or None

DEFAULT_MAX_TIMEOUT_MS = 60000
MIN_TIMEOUT_MS = 5000
MAX_TIMEOUT_MS = 240000
NAV_TIMEOUT_MS = 45000
CHALLENGE_POLL_S = 1.25

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "info").upper())
LOG = logging.getLogger("elminyawe")

# Flags that keep Chromium stable inside containers.
#  GPU stack intentionally untouched (WebGL fingerprints stay real).
DOCKER_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1280,720",
]

BROWSER_CHANNELS = {"chromium": "chromium", "chrome": "chrome", "msedge": "msedge"}

# Challenge detection - same signals FlareSolverr v3.5.2 uses
CHALLENGE_TITLES = [
    "Just a moment...",
    "DDoS-Guard",
    "Please wait...",
    "Checking your browser",
    "Attention Required",
]

CHALLENGE_SELECTORS = [
    "#cf-challenge-running",
    ".ray_id",
    ".attack-box",
    "#cf-please-wait",
    "#challenge-spinner",
    "#trk_jschal_js",
    "#turnstile-wrapper",
    ".lds-ring",
    "td.info #js_info",
    "div.vc div.text-box h2",
    "#challenge-running",
    "#challenge-stage",
    "#challenge-form",
    "div.cf-turnstile",
    "[id^='cf-chl-widget']",
    ".cf-browser-verification",
]

TURNSTILE_SELECTORS = ["input[name='cf-turnstile-response']"]

ACCESS_DENIED_SELECTORS = [
    "div.cf-error-title span.cf-code-label span",
    "#cf-error-details div.cf-error-overview h1",
]

# ---------------- sessions (in-memory) ----------------

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
SOLVE_SEM = threading.Semaphore(MAX_CONCURRENT)


class SolverError(Exception):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _clamp_timeout(raw) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_TIMEOUT_MS
    return max(MIN_TIMEOUT_MS, min(value, MAX_TIMEOUT_MS))


def parse_proxy(proxy):
    """host:port | scheme://host:port | scheme://user:pass@host:port -> patchright dict."""
    if not proxy or not str(proxy).strip():
        return None
    raw = str(proxy).strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        if not parts.hostname:
            return None
        default_port = 443 if parts.scheme == "https" else 80
        server = f"{parts.scheme or 'http'}://{parts.hostname}:{parts.port or default_port}"
        out = {"server": server}
        if parts.username:
            out["username"] = parts.username
        if parts.password:
            out["password"] = parts.password
        return out
    except Exception:
        return None


def _cookies_to_storage(cookies_in):
    """FlareSolverr-style cookie list -> Playwright storage cookies."""
    out = []
    for c in cookies_in or []:
        if not isinstance(c, dict) or "name" not in c:
            continue
        item = {
            "name": str(c.get("name")),
            "value": str(c.get("value", "")),
            "domain": str(c.get("domain") or ""),
            "path": str(c.get("path") or "/"),
        }
        if not item["domain"]:
            continue
        out.append(item)
    return out


def _to_fs_cookies(pw_cookies):
    """Playwright cookies -> FlareSolverr solution.cookies shape."""
    out = []
    for c in pw_cookies or []:
        expires = c.get("expires", -1)
        out.append({
            "name": c.get("name", ""),
            "value": c.get("value", ""),
            "domain": c.get("domain", ""),
            "path": c.get("path", "/"),
            "expires": expires if expires is not None else -1,
            "size": len(str(c.get("name", ""))) + len(str(c.get("value", ""))),
            "httpOnly": bool(c.get("httpOnly", False)),
            "secure": bool(c.get("secure", False)),
            "session": expires in (-1, -1.0, None),
            "sameSite": c.get("sameSite") or "Lax",
        })
    return out


def _has_cf_clearance(context) -> bool:
    try:
        for c in context.cookies():
            if str(c.get("name", "")).lower() == "cf_clearance":
                return True
    except Exception:
        pass
    return False


def _detect_state(page) -> str:
    """'challenge' | 'denied' | 'ok'"""
    try:
        title = (page.title() or "").lower()
    except Exception:
        title = ""
    for t in CHALLENGE_TITLES:
        if t.lower() in title:
            return "challenge"
    for sel in ACCESS_DENIED_SELECTORS:
        try:
            if page.query_selector(sel):
                return "denied"
        except Exception:
            pass
    for sel in CHALLENGE_SELECTORS + TURNSTILE_SELECTORS:
        try:
            if page.query_selector(sel):
                return "challenge"
        except Exception:
            pass
    return "ok"


def _try_click_turnstile(page) -> bool:
    """Theyka/Turnstile-Solver style checkbox click."""
    for sel in ("div.cf-turnstile", "#turnstile-wrapper", "div#cf-turnstile", ".cf-turnstile"):
        try:
            el = page.query_selector(sel)
            if el:
                el.click(timeout=800)
                return True
        except Exception:
            pass
    try:
        frame = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
        frame.locator("input[type=checkbox]").first.click(timeout=800)
        return True
    except Exception:
        pass
    try:
        frame = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
        frame.locator("body").first.click(timeout=800)
        return True
    except Exception:
        pass
    return False


# ---------------- core solve ----------------

def _solve_request(body: dict, cmd: str) -> dict:
    start = _now_ms()
    url = str(body.get("url") or "").strip()
    if not url:
        raise SolverError("Error: The 'url' parameter is mandatory.")
    if not url.startswith(("http://", "https://")):
        raise SolverError("Error: The 'url' parameter must start with 'http://' or 'https://'.")

    timeout_ms = _clamp_timeout(body.get("maxTimeout"))
    session_id = str(body.get("session") or "").strip() or None
    proxy = parse_proxy(body.get("proxy"))
    post_data = body.get("postData")
    cookies_in = body.get("cookies")

    with SESSIONS_LOCK:
        storage_state = SESSIONS.get(session_id) if session_id else None

    SOLVE_SEM.acquire()
    playwright = browser = context = page = None
    try:
        playwright = sync_playwright().start()
        launch_kwargs = {"args": DOCKER_ARGS, "headless": not HEADED}
        channel = BROWSER_CHANNELS.get(BROWSER_TYPE)
        if channel:
            launch_kwargs["channel"] = channel
        if USER_AGENT:
            launch_kwargs["args"] = DOCKER_ARGS + [f"--user-agent={USER_AGENT}"]
        browser = playwright.chromium.launch(**launch_kwargs)

        ctx_kwargs = {}
        if proxy:
            ctx_kwargs["proxy"] = proxy
        if storage_state:
            ctx_kwargs["storage_state"] = storage_state
        context = browser.new_context(**ctx_kwargs)

        if cookies_in:
            try:
                context.add_cookies(_cookies_to_storage(cookies_in))
            except Exception as e:
                LOG.warning("could not add cookies: %s", e)

        page = context.new_page()

        deadline = start / 1000 + timeout_ms / 1000
        message = "OK"
        status_code = 0
        headers = {}

        try:
            if cmd == "request.post":
                resp = context.request.post(
                    url,
                    data=post_data,
                    timeout=timeout_ms,
                )
                status_code = resp.status
                headers = dict(resp.headers)
                # also load it in the browser so scripts/cookies settle
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=min(timeout_ms, NAV_TIMEOUT_MS))
                except Exception:
                    pass
            else:
                resp = page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=min(timeout_ms, NAV_TIMEOUT_MS),
                )
                if resp is not None:
                    status_code = resp.status
                    headers = dict(resp.headers)
        except Exception as e:
            LOG.warning("navigation issue: %s", e)
            message = "OK"

        # --- challenge wait / solve loop ---
        challenge_seen = False
        while True:
            if _has_cf_clearance(context):
                challenge_seen = True
                message = "Challenge solved!"
                break

            state = _detect_state(page)
            if state == "denied":
                message = "Error: Access denied - the browser is blocked by the website."
                break
            if state != "challenge":
                message = "Challenge solved!" if challenge_seen else "OK"
                break
            challenge_seen = True
            if time.time() >= deadline:
                message = "Error: The challenge was not solved within maxTimeout."
                break
            _try_click_turnstile(page)
            time.sleep(CHALLENGE_POLL_S)

        try:
            html = page.content()
        except Exception:
            html = ""
        try:
            final_url = page.url or url
        except Exception:
            final_url = url
        try:
            user_agent = page.evaluate("navigator.userAgent")
        except Exception:
            user_agent = USER_AGENT or ""
        try:
            pw_cookies = context.cookies()
        except Exception:
            pw_cookies = []
        if not status_code:
            status_code = 200

        if session_id:
            try:
                with SESSIONS_LOCK:
                    SESSIONS[session_id] = context.storage_state()
            except Exception as e:
                LOG.warning("could not persist session state: %s", e)

        status = "error" if message.startswith("Error") else "ok"
        return {
            "status": status,
            "message": message,
            "startTimestamp": start,
            "endTimestamp": _now_ms(),
            "version": ENGINE_VERSION,
            "solution": {
                "url": final_url,
                "status": status_code,
                "headers": headers,
                "response": html,
                "cookies": _to_fs_cookies(pw_cookies),
                "userAgent": user_agent,
            },
        }
    finally:
        for closer in (
            lambda: context and context.close(),
            lambda: browser and browser.close(),
            lambda: playwright and playwright.stop(),
        ):
            try:
                closer()
            except Exception:
                pass
        SOLVE_SEM.release()


# ---------------- FlareSolverr-compatible /v1 handler ----------------

def solve_v1(body: dict) -> dict:
    start = _now_ms()
    cmd = str((body or {}).get("cmd") or "").strip()
    try:
        if cmd == "request.get":
            return _solve_request(body, "request.get")
        if cmd == "request.post":
            return _solve_request(body, "request.post")
        if cmd == "request.createSession":
            sid = uuid.uuid4().hex
            with SESSIONS_LOCK:
                SESSIONS[sid] = {"cookies": [], "origins": []}
            return {
                "status": "ok",
                "message": "Session created.",
                "startTimestamp": start,
                "endTimestamp": _now_ms(),
                "version": ENGINE_VERSION,
                "session": sid,
            }
        if cmd == "request.destroySession":
            sid = str(body.get("session") or "").strip()
            with SESSIONS_LOCK:
                existed = SESSIONS.pop(sid, None)
            return {
                "status": "ok",
                "message": "Session destroyed." if existed is not None else "Error: Session not found.",
                "startTimestamp": start,
                "endTimestamp": _now_ms(),
                "version": ENGINE_VERSION,
            }
        if cmd in ("requests.listSessions", "request.listSessions"):
            with SESSIONS_LOCK:
                ids = list(SESSIONS.keys())
            return {
                "status": "ok",
                "message": "Sessions listed.",
                "startTimestamp": start,
                "endTimestamp": _now_ms(),
                "version": ENGINE_VERSION,
                "sessions": ids,
            }
        raise SolverError(f"Error: Unknown cmd '{cmd}'.")
    except SolverError as e:
        return {
            "status": "error",
            "message": str(e),
            "startTimestamp": start,
            "endTimestamp": _now_ms(),
            "version": ENGINE_VERSION,
        }
    except Exception as e:
        LOG.exception("solve failed")
        return {
            "status": "error",
            "message": f"Error: {e}",
            "startTimestamp": start,
            "endTimestamp": _now_ms(),
            "version": ENGINE_VERSION,
        }


def engine_info() -> dict:
    return {
        "engine": ENGINE_VERSION,
        "browser": BROWSER_TYPE,
        "headed": HEADED,
        "display": os.environ.get("DISPLAY", ""),
        "max_concurrent_solves": MAX_CONCURRENT,
        "sessions": len(SESSIONS),
    }
PYENGINE

# ============================================================================
#  EMBEDDED FILE 2/4 : /app/elminyawe_api.py
#  ELMINYAWE smart gateway (result first, HTML last, clean JSON).
# ============================================================================
RUN cat > /app/elminyawe_api.py <<'PYAPI'
# ============================================================
# ELMINYAWE API — Smart Solver Gateway
#
# Endpoints:
#   GET  /         -> service info
#   GET  /health   -> solver status
#   GET  /solve    -> smart solving: /solve?url=<target>&session=<opt>&maxTimeout=<opt>
#   POST /v1       -> full solving API (important data first, HTML last)
# ============================================================

from fastapi import FastAPI, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from typing import Optional

import os
import re
import json

from elminyawe_engine import solve_v1 as engine_solve_v1, engine_info

# ============================================================
# CLEAN JSON OUTPUT
# - never emits \uXXXX escapes (real UTF-8 characters instead)
# - decodes leftover escape sequences INSIDE values
#   (e.g. \u003C -> '<' , \u0026 -> '&' , \/ -> '/')
# - keeps control-char escapes like \u000A intact (safe for JS
#   code embedded in the returned HTML)
# ============================================================

_PAIR_RE = re.compile(r"\\u([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})")
_UNI_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def clean_text(value):
    if not isinstance(value, str) or "\\" not in value:
        return value

    def _pair(m):
        hi = int(m.group(1), 16)
        lo = int(m.group(2), 16)
        return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))

    def _uni(m):
        code = int(m.group(1), 16)
        if code < 0x20 or code == 0x7F:
            return m.group(0)
        if 0xD800 <= code <= 0xDFFF:
            return m.group(0)
        return chr(code)

    out = _PAIR_RE.sub(_pair, value)
    out = _UNI_RE.sub(_uni, out)
    out = out.replace("\\/", "/")
    return out


def clean_structure(obj):
    if isinstance(obj, str):
        return clean_text(obj)
    if isinstance(obj, dict):
        return {
            clean_text(k) if isinstance(k, str) else k: clean_structure(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [clean_structure(v) for v in obj]
    return obj


class CleanJSONResponse(JSONResponse):
    def render(self, content):
        return json.dumps(
            clean_structure(content),
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")

SERVICE = "ELMINYAWE"
DEVELOPER = "ELMINYAWE"

app = FastAPI(
    default_response_class=CleanJSONResponse,
    title="ELMINYAWE",
    description="ELMINYAWE API - Smart Solver Gateway",
    version="2.0.0"
)


# ============================================================
# SMART EXTRACTION (cookies / tokens)
# ============================================================

INPUT_NAME_FIRST = re.compile(
    r'<input\b[^>]*?name\s*=\s*["\']([^"\']+)["\'][^>]*?value\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE | re.DOTALL
)

INPUT_VALUE_FIRST = re.compile(
    r'<input\b[^>]*?value\s*=\s*["\']([^"\']*)["\'][^>]*?name\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL
)

# technical token fields only (turnstile / csrf / hidden challenge fields ...)
TOKEN_NAME_FILTER = re.compile(
    r"(^cf|__cf|turnstile|captcha|recaptcha|hcaptcha|csrf|xsrf|token|jsl|mdrd|chl|challenge)",
    re.IGNORECASE
)

MAX_HTML_TOKENS = 25
MAX_TOKEN_LENGTH = 8192


def extract_html_tokens(html):

    """Extract useful tokens (turnstile / csrf / hidden challenge fields) from HTML."""

    tokens = {}

    if not html or not isinstance(html, str):
        return tokens

    for name, value in INPUT_NAME_FIRST.findall(html):

        name = name.strip()
        value = value.strip()

        if value and len(value) <= MAX_TOKEN_LENGTH and TOKEN_NAME_FILTER.search(name):
            tokens[name] = value

    for value, name in INPUT_VALUE_FIRST.findall(html):

        name = name.strip()
        value = value.strip()

        if value and len(value) <= MAX_TOKEN_LENGTH and TOKEN_NAME_FILTER.search(name):
            if name not in tokens:
                tokens[name] = value

    if len(tokens) > MAX_HTML_TOKENS:
        tokens = dict(list(tokens.items())[:MAX_HTML_TOKENS])

    return tokens


def is_cf_cookie(name):

    n = str(name).lower()
    return n.startswith("cf") or n.startswith("__cf")


# ============================================================
# BRANDING (the solver stays completely hidden)
# ============================================================

def deep_rebrand(value, skip_key=None):

    if isinstance(value, dict):
        return {k: deep_rebrand(v, skip_key=k) for k, v in value.items()}

    if isinstance(value, list):
        return [deep_rebrand(v) for v in value]

    if isinstance(value, str):

        if skip_key == "response":
            # the target site HTML -> never touched
            return value

        if "FlareSolverr" in value:
            value = value.replace("FlareSolverr", "ELMINYAWE Solver")

        if "flaresolverr" in value.lower():
            value = re.sub(r"flaresolverr", "elminyawe", value, flags=re.IGNORECASE)

        return value

    return value


# ============================================================
# SMART RESPONSE (important values FIRST, HTML LAST)
# ============================================================

def reorder_solution(solution):

    """Reorder solution keys -> the HTML "response" is ALWAYS the last key."""

    ordered = {}

    for key in ("url", "status", "userAgent", "cookies", "headers"):
        if key in solution:
            ordered[key] = solution[key]

    for key, value in solution.items():
        if key != "response" and key not in ordered:
            ordered[key] = value

    if "response" in solution:
        ordered["response"] = solution["response"]

    return ordered


def build_result(solution, message, session_value=None, start_ts=None, end_ts=None):

    cookies = solution.get("cookies") or []
    if not isinstance(cookies, list):
        cookies = []

    cookies_map = {}

    for cookie in cookies:
        if isinstance(cookie, dict) and cookie.get("name"):
            cookies_map[str(cookie["name"])] = cookie.get("value", "")

    cf_tokens = {n: v for n, v in cookies_map.items() if is_cf_cookie(n)}
    html_tokens = extract_html_tokens(solution.get("response"))

    challenge_solved = ("cf_clearance" in cookies_map) or ("challenge solved" in str(message).lower())

    result = {
        "url": solution.get("url"),
        "http_status": solution.get("status"),
        "user_agent": solution.get("userAgent"),
        "session": session_value,
        "challenge_solved": challenge_solved,
        "cookies": cookies,
        "cookies_map": cookies_map,
        "cf_tokens": cf_tokens,
        "html_tokens": html_tokens,
        "headers": solution.get("headers") if isinstance(solution.get("headers"), dict) else {}
    }

    if isinstance(start_ts, int) and isinstance(end_ts, int):
        result["timing"] = {
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "elapsed_ms": max(0, end_ts - start_ts)
        }

    return result


def build_smart_response(data, session_value=None):

    """Full response: "result" (important values) FIRST, "solution" (HTML) LAST."""

    data = deep_rebrand(data)

    message = data.get("message") if isinstance(data.get("message"), str) else data.get("msg")
    solution = data.get("solution") if isinstance(data.get("solution"), dict) else None

    ordered = {}

    ordered["status"] = data.get("status")
    ordered["message"] = message
    ordered["service"] = SERVICE
    ordered["developer"] = DEVELOPER

    if solution is not None:
        ordered["result"] = build_result(
            solution,
            message or "",
            session_value,
            data.get("startTimestamp"),
            data.get("endTimestamp")
        )

    for key, value in data.items():
        if key != "solution" and key not in ordered:
            ordered[key] = value

    if solution is not None:
        ordered["solution"] = reorder_solution(solution)

    return ordered


def build_branded_response(data):

    """For sessions commands / errors: branding only, keep everything."""

    data = deep_rebrand(data)

    ordered = {}

    for key in ("status", "message", "msg"):
        if key in data:
            ordered[key] = data[key]

    ordered["service"] = SERVICE
    ordered["developer"] = DEVELOPER

    for key, value in data.items():
        if key not in ordered:
            ordered[key] = value

    return ordered


# ============================================================
# SOLVER CALL (shared by /solve and /v1)
# ============================================================

def call_solver(body, session_value=None):

    try:

        data = engine_solve_v1(body)

        if isinstance(data, dict) and isinstance(data.get("solution"), dict):
            content = build_smart_response(data, session_value)
        elif isinstance(data, dict):
            content = build_branded_response(data)
        else:
            content = data

        return CleanJSONResponse(
            status_code=200,
            content=content
        )

    except Exception as e:

        return CleanJSONResponse(
            status_code=500,
            content={
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": str(e)
            }
        )


# =
# ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "ELMINYAWE",
        "developer": "ELMINYAWE",
        "version": "2.0.0",
        "api_port": 8191,
        "solver_port": 8080,
        "endpoints": {
            "solve": "GET /solve?url=<target-url>&session=<optional>&maxTimeout=<optional>",
            "full_api": "POST /v1",
            "health": "GET /health"
        }
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "online",
        "service": SERVICE,
        "developer": DEVELOPER,
        "solver": engine_info()
    }


# =
# SMART SOLVE  ->  /solve?url=<target>&session=<opt>&maxTimeout=<opt>
# ============================================================

@app.get("/solve")
def solve_get(
    url: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    maxTimeout: Optional[int] = Query(None, alias="maxTimeout")
):

    if not url or not url.strip():

        return CleanJSONResponse(
            status_code=400,
            content={
                "status": "error",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": "Missing required parameter: url  (usage: /solve?url=https://example.com)"
            }
        )

    url = url.strip()

    if not (url.startswith("http://") or url.startswith("https://")):

        return CleanJSONResponse(
            status_code=400,
            content={
                "status": "error",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": "Invalid url: must start with http:// or https://"
            }
        )

    body = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": maxTimeout if maxTimeout is not None else 60000
    }

    if session and session.strip():
        body["session"] = session.strip()

    return call_solver(body, body.get("session"))


# ============================================================
# FULL API  ->  POST /v1
# ============================================================

@app.post("/v1")
async def solve_v1(request: Request):

    try:

        # Receive RAW body
        raw_body = await request.body()

        # Parse JSON
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            return CleanJSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "service": SERVICE,
                    "developer": DEVELOPER,
                    "error": "Invalid JSON",
                    "details": str(e)
                }
            )

        if not isinstance(body, dict):
            return CleanJSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "service": SERVICE,
                    "developer": DEVELOPER,
                    "error": "Invalid payload: JSON object required"
                }
            )

        session_value = body.get("session")

        # solve in a worker thread (keeps the API responsive during long solves)
        return await run_in_threadpool(call_solver, body, session_value)

    except Exception as e:

        return CleanJSONResponse(
            status_code=500,
            content={
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": str(e)
            }
        )


# ============================================================
# 404
# ============================================================

@app.api_route(
    "/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE"
    ]
)
async def catch_all(request: Request, path: str):

    return CleanJSONResponse(
        status_code=404,
        content={
            "service": SERVICE,
            "developer": DEVELOPER,
            "error": "Endpoint not found"
        }
    )
PYAPI

# ============================================================================
#  EMBEDDED FILE 3/4 : /app/elminyawe_launch.py
#  One process, explicit listener sockets (8191 + platform PORT alias).
# ============================================================================
RUN cat > /app/elminyawe_launch.py <<'PYLAUNCH'
"""ELMINYAWE launcher: one process, one app, explicit listener sockets.

Port architecture (proven in the "turn" project):
  - ELMINYAWE_PORT (default 8191) -> the primary public API port.
  - PORT (platform-injected, e.g. 8080) -> bound as a compat alias by the
    SAME process, so a platform target-port mismatch cannot 502.
  - The solving engine is in-process (private Chromium pipe, no TCP port).
"""
import asyncio
import os
import socket
import sys


def resolve_listeners(env=None):
    """Return the ordered unique port list."""
    env = os.environ if env is None else env
    try:
        primary = int(str(env.get("ELMINYAWE_PORT", "8191")).strip() or 8191)
    except (TypeError, ValueError):
        primary = 8191
    if not (1 <= primary <= 65535):
        primary = 8191

    ports = [primary]
    raw = str(env.get("PORT", "") or "").strip()
    if raw.isdigit():
        alias = int(raw)
        if 1 <= alias <= 65535 and alias != primary:
            ports.append(alias)
    return ports


def open_sockets(host, ports):
    socks = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(2048)
        s.set_inheritable(True)
        socks.append(s)
    return socks


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    ports = resolve_listeners()
    socks = open_sockets(host, ports)
    os.environ["ELMINYAWE_LISTENERS"] = ",".join(str(p) for p in ports)

    import uvicorn

    for port in ports:
        print(f"[ELMINYAWE] API listening on {host}:{port}", flush=True)
    print("[ELMINYAWE] engine: in-process (patchright + Chromium, no TCP port)",
          flush=True)

    cfg = uvicorn.Config("elminyawe_api:app", log_level="info", workers=1)
    server = uvicorn.Server(cfg)
    asyncio.run(server.serve(sockets=socks))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
PYLAUNCH

# ============================================================================
#  EMBEDDED FILE 4/4 : /app/start_elminyawe.sh
#  Entrypoint - virtual display, preflight checks, single process.
# ============================================================================
RUN cat > /app/start_elminyawe.sh <<'SHELLSTART'
#!/usr/bin/env bash
# ============================================================
#  ELMINYAWE Smart Solver - container entrypoint
#  Single process: the ELMINYAWE API + in-process solving engine.
#  Headed stealth mode by default (Xvfb :99); headless stays
#  available via ELMINYAWE_HEADLESS=true.
#  (entrypoint proven on this platform by the "turn" project)
# ============================================================
set -e
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)"
export PYTHONUNBUFFERED=1

HOST="${HOST:-0.0.0.0}"
ELMINYAWE_PORT="${ELMINYAWE_PORT:-8191}"
export ELMINYAWE_PORT

echo ""
echo "=============================================="
echo "              ELMINYAWE"
echo "          Smart Solver API"
echo "=============================================="
echo ""

#  headed stealth mode (default): serve the browser a virtual display
if [ "${ELMINYAWE_HEADLESS:-false}" = "false" ] && [ -z "${DISPLAY:-}" ]; then
  if command -v Xvfb >/dev/null 2>&1; then
    Xvfb :99 -screen 0 1280x720x24 -ac -nolisten tcp >/dev/null 2>&1 &
    export DISPLAY=:99
    #  wait until the display socket is actually ready (up to ~5s)
    for _ in $(seq 1 20); do
      [ -S /tmp/.X11-unix/X99 ] && break
      sleep 0.25
    done
    echo "[ELMINYAWE] virtual display ready on :99 (headed stealth mode)"
  else
    echo "[ELMINYAWE] WARNING: Xvfb not found, staying headless"
  fi
fi

# preflight: engine driver + browser availability (non-fatal warnings)
python - <<'PY'
import glob, os
try:
    import patchright  # noqa: F401
    print("[ELMINYAWE] engine driver: ready")
except Exception as exc:
    print(f"[ELMINYAWE] WARNING: engine driver import failed: {exc}")
cache = os.path.expanduser("~/.cache/ms-playwright")
hits = sorted(glob.glob(os.path.join(cache, "chromium-*")))
chrome = bool(glob.glob(os.path.join(cache, "chrome-*"))) or os.path.exists("/opt/google/chrome/chrome")
if hits:
    detail = os.path.basename(hits[-1]) + (" + chrome channel" if chrome else "")
    print(f"[ELMINYAWE] browser: ready -> {detail}")
else:
    print("[ELMINYAWE] WARNING: chromium not found in patchright cache")
PY

echo "[ELMINYAWE] Starting ELMINYAWE API..."
echo "[ELMINYAWE] API: ${HOST}:${ELMINYAWE_PORT}"
echo ""

exec python elminyawe_launch.py
SHELLSTART

RUN chmod +x /app/start_elminyawe.sh

EXPOSE 8191 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request as u,sys,os; p=os.environ.get('ELMINYAWE_PORT','8191'); r=u.urlopen('http://127.0.0.1:'+p+'/health',timeout=4); sys.exit(0 if r.getcode()==200 else 1)" || exit 1

CMD ["/app/start_elminyawe.sh"]
