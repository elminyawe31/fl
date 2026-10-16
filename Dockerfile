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

# ----------------------------------------------------------------
# Pre-patch chromedriver AT BUILD TIME with the exact same patch
# undetected_chromedriver applies (cdc block -> marker). At runtime the
# rootfs is read-only, so the patched binary must be ready beforehand.
# Verified byte-identical with undetected_chromedriver.patch_exe().
# ----------------------------------------------------------------
RUN cat > /app/patch_chromedriver.py <<'PYEOF'
import re

path = "/app/chromedriver"

with open(path, "rb") as f:
    content = f.read()

match = re.search(rb"\{window\.cdc.*?;\}", content)

if not match:
    print("WARN: cdc block not found - runtime fallback will handle it")
else:
    old = match.group(0)
    new = b'{console.log("undetected chromedriver 1337!")}'.ljust(len(old), b" ")
    content = content.replace(old, new)
    with open(path, "wb") as f:
        f.write(content)
    assert b"undetected chromedriver" in open(path, "rb").read(), "patch marker not written"
    print("chromedriver pre-patched OK ->", path)
PYEOF
RUN /usr/local/bin/python /app/patch_chromedriver.py


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

SOLVER_URL = os.environ.get("SOLVER_URL") or "http://127.0.0.1:8080"
SOLVE_TIMEOUT = 180

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
            return CleanJSONResponse(
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

        return CleanJSONResponse(
            status_code=response.status_code,
            content=content
        )

    except requests.exceptions.Timeout:

        return CleanJSONResponse(
            status_code=504,
            content={
                "status": "error",
                "service": SERVICE,
                "developer": DEVELOPER,
                "error": "Solving timeout"
            }
        )

    except requests.exceptions.RequestException as e:

        return CleanJSONResponse(
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

        return CleanJSONResponse(
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

        return CleanJSONResponse(
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

mkdir -p /data 2>/dev/null

if touch /data/.elminyawe_write_test 2>/dev/null; then

    rm -f /data/.elminyawe_write_test

    export HOME=/data
    export XDG_CONFIG_HOME=/data/.config
    export XDG_CACHE_HOME=/data/.cache
    export XDG_DATA_HOME=/data/.local/share
    export TMPDIR=/data/tmp
    export PYTHONDONTWRITEBYTECODE=1

    mkdir -p /data/.config/chromium/"Crash Reports"/pending \
             /data/.cache \
             /data/.local/share/undetected_chromedriver \
             /data/tmp

    echo "[ELMINYAWE] Runtime dirs redirected to /data (read-only rootfs detected)"

fi

# ============================================================
# CHROMEDRIVER (must be executable AND patchable)
# /data may be mounted 'noexec' -> NEVER execute from /data directly.
# utils.py is patched to use /data/chromedriver, so point that path
# (via symlink) to a place where exec actually works.
# ============================================================

rm -f /data/chromedriver 2>/dev/null

if grep -qa "undetected chromedriver" /app/chromedriver 2>/dev/null; then

    # pre-patched at build time -> run it straight from the image
    ln -sf /app/chromedriver /data/chromedriver
    echo "[ELMINYAWE] chromedriver: using pre-patched driver from image"

else

    CD_DIR=""

    for d in /tmp /dev/shm /data; do

        printf '#!/bin/sh\necho OK\n' > "$d/.exec_test" 2>/dev/null || continue
        chmod +x "$d/.exec_test" 2>/dev/null || continue

        if "$d/.exec_test" >/dev/null 2>&1; then
            CD_DIR="$d"
            rm -f "$d/.exec_test"
            break
        fi

        rm -f "$d/.exec_test"

    done

    if [ -n "$CD_DIR" ]; then
        cp /app/chromedriver "$CD_DIR/chromedriver"
        chmod +x "$CD_DIR/chromedriver"
        ln -sf "$CD_DIR/chromedriver" /data/chromedriver
        echo "[ELMINYAWE] chromedriver: runtime copy -> $CD_DIR/chromedriver"
    else
        echo "[ELMINYAWE] WARNING: no exec-capable writable dir found!"
    fi

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
