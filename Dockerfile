FROM ghcr.io/flaresolverr/flaresolverr:latest

USER root

RUN pip install --no-cache-dir fastapi uvicorn requests

# ----------------------------------------------------------------
# Deplexo compatibility: the container rootfs is READ-ONLY at
# runtime (only /data and /tmp are writable). undetected_chromedriver
# normally patches /app/chromedriver IN PLACE, so make FlareSolverr
# use a writable copy on the /data volume instead.
# ----------------------------------------------------------------
RUN sed -i 's#/app/chromedriver#/data/chromedriver#g' /app/utils.py


# ============================================================
# ELMINYAWE API
# ============================================================

RUN cat > /app/elminyawe_api.py <<'PY'
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
import requests
import json

SOLVER_URL = os.environ.get("SOLVER_URL") or "http://127.0.0.1:8080"
SOLVE_TIMEOUT = 180

SERVICE = "ELMINYAWE"
DEVELOPER = "ELMINYAWE"

app = FastAPI(
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

        response = requests.post(
            f"{SOLVER_URL}/v1",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            timeout=SOLVE_TIMEOUT
        )

        try:
            data = response.json()
        except Exception:
            return JSONResponse(
                status_code=response.status_code,
                content={
                    "service": SERVICE,
                    "developer": DEVELOPER,
                    "response": response.text
                }
            )

        if isinstance(data, dict) and isinstance(data.get("solution"), dict):
            content = build_smart_response(data, session_value)
        elif isinstance(data, dict):
            content = build_branded_response(data)
        else:
            content = data

        return JSONResponse(
            status_code=response.status_code,
            content=content
        )

    except requests.exceptions.Timeout:

        return JSONResponse(
            status_code=504,
            content={
                "status": "error",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": "Solving timeout"
            }
        )

    except requests.exceptions.RequestException as e:

        return JSONResponse(
            status_code=502,
            content={
                "status": "error",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": "Solver connection failed",
                "details": str(e)
            }
        )

    except Exception as e:

        return JSONResponse(
            status_code=500,
            content={
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": str(e)
            }
        )


# ============================================================
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

    try:

        response = requests.get(
            f"{SOLVER_URL}/health",
            timeout=10
        )

        try:
            solver_info = deep_rebrand(response.json())
        except Exception:
            solver_info = {"raw": response.text[:500]}

        return {
            "status": "online",
            "service": SERVICE,
            "developer": DEVELOPER,
            "solver": solver_info
        }

    except Exception as e:

        return JSONResponse(
            status_code=502,
            content={
                "status": "offline",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": str(e)
            }
        )


# ============================================================
# SMART SOLVE  ->  /solve?url=<target>&session=<opt>&maxTimeout=<opt>
# ============================================================

@app.get("/solve")
def solve_get(
    url: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    maxTimeout: Optional[int] = Query(None, alias="maxTimeout")
):

    if not url or not url.strip():

        return JSONResponse(
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

        return JSONResponse(
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
            return JSONResponse(
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
            return JSONResponse(
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

        return JSONResponse(
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

    return JSONResponse(
        status_code=404,
        content={
            "service": SERVICE,
            "developer": DEVELOPER,
            "error": "Endpoint not found"
        }
    )
PY


# ============================================================
# START SCRIPT
# ============================================================

RUN cat > /app/start_elminyawe.sh <<'SH'
#!/bin/sh

echo ""
echo "=============================================="
echo "              ELMINYAWE"
echo "          Smart Solver API"
echo "=============================================="
echo ""

# ============================================================
# WRITABLE RUNTIME DIRS
# On Deplexo the root filesystem is READ-ONLY: only /data
# (persistent volume) and /tmp are writable. undetected_chromedriver
# creates ~/.local/share/undetected_chromedriver and Chromium writes
# its profile + crashpad under $HOME -> redirect everything to /data.
# ============================================================

if touch /data/.elminyawe_write_test 2>/dev/null; then

    rm -f /data/.elminyawe_write_test

    export HOME=/data
    export XDG_CONFIG_HOME=/data/.config
    export XDG_CACHE_HOME=/data/.cache
    export XDG_DATA_HOME=/data/.local/share
    export TMPDIR=/data/tmp

    mkdir -p /data/.config/chromium/"Crash Reports"/pending \
             /data/.cache \
             /data/.local/share/undetected_chromedriver \
             /data/tmp

    # writable copy of chromedriver (undetected_chromedriver patches
    # the binary in place on first run -> must NOT be on read-only /app)
    if [ ! -x /data/chromedriver ]; then
        cp /app/chromedriver /data/chromedriver 2>/dev/null
        chmod +x /data/chromedriver 2>/dev/null
    fi

    echo "[ELMINYAWE] Runtime dirs redirected to /data (read-only rootfs detected)"

fi

echo "[ELMINYAWE] Starting solver..."
echo "[ELMINYAWE] Internal solver: 127.0.0.1:8080"

export HOST=127.0.0.1
export PORT=8080

/usr/local/bin/python -u /app/flaresolverr.py &

FLARE_PID=$!

echo "[ELMINYAWE] Solver PID: $FLARE_PID"

echo "[ELMINYAWE] Waiting for solver..."

i=0

while [ $i -lt 60 ]; do

    if /usr/local/bin/python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).getcode()==200 else 1)" >/dev/null 2>&1; then
        echo "[ELMINYAWE] Solver READY!"
        break
    fi

    i=$((i + 1))
    sleep 1

done

if ! kill -0 "$FLARE_PID" 2>/dev/null; then

    echo "[ELMINYAWE] ERROR: Solver stopped!"

    exit 1

fi

echo ""
echo "[ELMINYAWE] Starting ELMINYAWE API..."
echo "[ELMINYAWE] API: 0.0.0.0:8191"
echo "[ELMINYAWE] Solver: 127.0.0.1:8080"
echo ""

/usr/local/bin/python -m uvicorn elminyawe_api:app \
    --host 0.0.0.0 \
    --port 8191 &

API_PID=$!

trap 'kill -TERM "$API_PID" "$FLARE_PID" 2>/dev/null; exit 0' TERM INT

# supervision: if one of the two processes stops -> stop the container
# (docker restart policy brings everything back clean)
while true; do

    if ! kill -0 "$FLARE_PID" 2>/dev/null; then
        echo "[ELMINYAWE] ERROR: Solver died! Stopping container..."
        kill -TERM "$API_PID" 2>/dev/null
        exit 1
    fi

    if ! kill -0 "$API_PID" 2>/dev/null; then
        echo "[ELMINYAWE] ERROR: API died! Stopping container..."
        kill -TERM "$FLARE_PID" 2>/dev/null
        exit 1
    fi

    sleep 2

done
SH

RUN chmod +x /app/start_elminyawe.sh


# ============================================================
# ENVIRONMENT
# ============================================================

ENV LOG_LEVEL=info
ENV LOG_HTML=false
ENV CAPTCHA_SOLVER=none
ENV LANG=en
ENV TZ=UTC


# ============================================================
# PORTS
# (8191 public API only - the internal solver port stays hidden)
# ============================================================

EXPOSE 8191


# ============================================================
# START
# ============================================================

CMD ["/app/start_elminyawe.sh"]
