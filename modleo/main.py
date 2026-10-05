"""
Modleo backend
Chat UI -> FastAPI -> third-party LLM API

Run:
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

# ============================================================
# CONFIG
# ============================================================

DATA = Path(os.getenv("DATA_DIR", "data"))
DATA.mkdir(parents=True, exist_ok=True)

STORE = DATA / "store.json"

UA = os.getenv(
    "UPSTREAM_UA",
    "Modleo/1.0 (+https://your-domain.example)"
)

REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "180"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "20"))

app = FastAPI(
    title="Modleo",
    docs_url=None,
    redoc_url=None,
)

# ============================================================
# CORS
# ============================================================

# Example:
# FRONTEND_ORIGINS=https://modleo.example.com,http://localhost:3000

FRONTEND_ORIGINS = [
    x.strip()
    for x in os.getenv("FRONTEND_ORIGINS", "").split(",")
    if x.strip()
]

if FRONTEND_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=FRONTEND_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

# ============================================================
# STORAGE
# ============================================================


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()


def _new_user(username: str, password: str) -> dict:
    salt = secrets.token_hex(16)

    return {
        "username": username.lower(),
        "salt": salt,
        "hash": _hash(password, salt),
    }


def load() -> dict:
    if STORE.exists():
        try:
            return json.loads(STORE.read_text(encoding="utf-8"))
        except Exception:
            pass

    admin_user = os.getenv("ADMIN_USER", "demouser1")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_password:
        # Do not use a predictable production password.
        admin_password = secrets.token_urlsafe(18)

    db = {
        "secret": secrets.token_hex(32),
        "providers": [],
        "user": _new_user(admin_user, admin_password),
    }

    seed = os.getenv("PROVIDERS_JSON")

    if seed:
        try:
            providers = json.loads(seed)

            for provider in providers:
                db["providers"].append(
                    {
                        "id": secrets.token_hex(4),
                        "name": provider["name"],
                        "base_url": clean_url(provider["base_url"]),
                        "api_key": provider.get("api_key", ""),
                        "models": provider.get("models", []),
                    }
                )

        except Exception as exc:
            raise RuntimeError(
                f"Invalid PROVIDERS_JSON: {exc}"
            ) from exc

    save(db)

    return db


def save(db: dict) -> None:
    tmp = STORE.with_suffix(".tmp")

    tmp.write_text(
        json.dumps(db, indent=2),
        encoding="utf-8",
    )

    tmp.replace(STORE)


DB = load()

SECRET = (
    os.getenv("SECRET_KEY")
    or DB["secret"]
).encode("utf-8")

# ============================================================
# AUTH
# ============================================================


def _sign(payload: str) -> str:
    return hmac.new(
        SECRET,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def make_token(user: str) -> str:
    payload = f"{user}|{int(time.time()) + 7 * 86400}"

    encoded = base64.urlsafe_b64encode(
        payload.encode("utf-8")
    ).decode("ascii")

    return encoded + "." + _sign(payload)


def read_token(token: str | None):
    if not token:
        return None

    try:
        encoded, signature = token.rsplit(".", 1)

        payload = base64.urlsafe_b64decode(
            encoded.encode("ascii")
        ).decode("utf-8")

        expected = _sign(payload)

        if not hmac.compare_digest(
            signature,
            expected,
        ):
            return None

        username, expiry = payload.rsplit("|", 1)

        if int(expiry) <= int(time.time()):
            return None

        return username

    except Exception:
        return None


def set_cookie(
    response: Response,
    request: Request,
    user: str,
):
    forwarded_proto = request.headers.get(
        "x-forwarded-proto"
    )

    secure = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key="modleo",
        value=make_token(user),
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=7 * 86400,
        path="/",
    )


def require_user(request: Request) -> str:
    username = read_token(
        request.cookies.get("modleo")
    )

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Not signed in",
        )

    return username


FAILS: dict[str, list] = {}

# ============================================================
# URL / SECURITY
# ============================================================


def clean_url(url: str) -> str:
    url = url.strip().rstrip("/")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            400,
            "Base URL must start with http:// or https://",
        )

    if not parsed.netloc:
        raise HTTPException(
            400,
            "Invalid provider URL",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            400,
            "Credentials must not be embedded in the URL",
        )

    return url


def validate_provider_host(url: str) -> None:
    """
    Basic SSRF protection.

    Prevents the gateway from accidentally being used to
    access localhost/private network addresses.
    """

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(400, "Invalid provider hostname")

    hostname_lower = hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "host.docker.internal",
    }

    if hostname_lower in blocked_names:
        raise HTTPException(
            400,
            "Private/local provider addresses are not allowed",
        )

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (
                443 if parsed.scheme == "https" else 80
            ),
            type=socket.SOCK_STREAM,
        )

        for item in addresses:
            address = item[4][0]

            ip = ipaddress.ip_address(address)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
            ):
                raise HTTPException(
                    400,
                    "Private/internal provider addresses are not allowed",
                )

    except socket.gaierror as exc:
        raise HTTPException(
            400,
            f"Cannot resolve provider host: {hostname}",
        ) from exc


# ============================================================
# HTTP CLIENT
# ============================================================


def headers_for(key: str) -> dict:
    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/event-stream, */*",
        "Content-Type": "application/json",
    }

    if key:
        headers["Authorization"] = f"Bearer {key}"

    return headers


def create_client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        timeout=REQUEST_TIMEOUT,
        connect=CONNECT_TIMEOUT,
        read=REQUEST_TIMEOUT,
        write=REQUEST_TIMEOUT,
        pool=REQUEST_TIMEOUT,
    )

    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
        ),
    )


# ============================================================
# ERROR HANDLING
# ============================================================


def extract_error_message(text: str) -> str:
    if not text:
        return ""

    try:
        data = json.loads(text)

        error = data.get("error")

        if isinstance(error, dict):
            message = (
                error.get("message")
                or error.get("detail")
                or error.get("type")
            )

            if message:
                return str(message)

        if isinstance(error, str):
            return error

        message = data.get("message")

        if message:
            return str(message)

    except Exception:
        pass

    return text.strip()


def explain(
    status: int,
    text: str,
    headers: httpx.Headers | None = None,
) -> dict:

    text = text or ""

    msg = extract_error_message(text)

    low = (
        msg + " " + text
    ).lower()

    content_type = ""

    if headers:
        content_type = headers.get(
            "content-type",
            "",
        ).lower()

    # --------------------------------------------------------
    # Cloudflare / HTML firewall page
    # --------------------------------------------------------

    if (
        "text/html" in content_type
        or text.lstrip().startswith("<!doctype")
        or text.lstrip().startswith("<html")
        or "<title>" in text.lower()
    ):

        title_match = re.search(
            r"<title>\s*(.*?)\s*</title>",
            text,
            re.I | re.S,
        )

        code_match = re.search(
            r"(?:error code|ray id)[^\d]*(\d{3,4})",
            text,
            re.I,
        )

        ray_match = re.search(
            r"Ray ID[:\s]*([a-zA-Z0-9]+)",
            text,
            re.I,
        )

        details = []

        if title_match:
            details.append(
                re.sub(
                    r"\s+",
                    " ",
                    title_match.group(1),
                ).strip()
            )

        if code_match:
            details.append(
                f"HTTP/Cloudflare code {code_match.group(1)}"
            )

        if ray_match:
            details.append(
                f"Ray ID {ray_match.group(1)}"
            )

        return {
            "kind": "firewall",
            "title": "Provider firewall blocked the server",
            "hint": (
                "The third-party gateway returned an HTML "
                "firewall/block page instead of an LLM API "
                "response. This is not a browser CORS problem. "
                "The provider is blocking the network/IP used "
                "by this backend."
            ),
            "scope": "provider",
            "status": status,
            "msg": " · ".join(details)[:500]
            or "Provider returned an HTML block page.",
        }

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if (
        status == 401
        or re.search(
            r"invalid token|invalid api key|incorrect api key|unauthorized",
            low,
        )
    ):
        return {
            "kind": "auth",
            "title": "API key rejected",
            "hint": (
                "The provider rejected the API key. "
                "Check the key, provider endpoint and "
                "authentication format."
            ),
            "scope": "provider",
            "status": status,
            "msg": msg[:500],
        }

    # --------------------------------------------------------
    # Forbidden
    # --------------------------------------------------------

    if status == 403:
        return {
            "kind": "denied",
            "title": "Provider denied the request",
            "hint": (
                "The provider refused this request. "
                "Check account permissions, model access, "
                "IP restrictions and provider policy."
            ),
            "scope": "provider",
            "status": status,
            "msg": msg[:500],
        }

    # --------------------------------------------------------
    # Rate limit
    # --------------------------------------------------------

    if (
        status == 429
        or re.search(
            r"rate.?limit|too many requests",
            low,
        )
    ):
        return {
            "kind": "rate",
            "title": "Provider rate limit",
            "hint": (
                "The provider is rate limiting requests. "
                "Wait and retry or use another provider/model."
            ),
            "scope": "retry",
            "status": status,
            "msg": msg[:500],
        }

    # --------------------------------------------------------
    # Credits
    # --------------------------------------------------------

    if (
        status == 402
        or re.search(
            r"quota|insufficient|credit|balance|billing|arrear",
            low,
        )
    ):
        return {
            "kind": "quota",
            "title": "Provider credits unavailable",
            "hint": (
                "The provider account appears to have "
                "insufficient credits or billing capacity."
            ),
            "scope": "provider",
            "status": status,
            "msg": msg[:500],
        }

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    if (
        status == 404
        or re.search(
            r"model.*(?:not found|does not exist|not available)"
            r"|no available channel",
            low,
        )
    ):
        return {
            "kind": "model",
            "title": "Model not available",
            "hint": (
                "The provider does not appear to expose "
                "this model for this API key."
            ),
            "scope": "model",
            "status": status,
            "msg": msg[:500],
        }

    # --------------------------------------------------------
    # Provider server error
    # --------------------------------------------------------

    if status >= 500:
        return {
            "kind": "server",
            "title": "Provider server error",
            "hint": (
                "The provider returned a server-side error. "
                "Retry or switch provider."
            ),
            "scope": "retry",
            "status": status,
            "msg": msg[:500],
        }

    return {
        "kind": "other",
        "title": f"Request failed (HTTP {status})",
        "hint": "Inspect the provider response.",
        "scope": "none",
        "status": status,
        "msg": msg[:500],
    }


def net_error(
    exc: Exception,
    base: str,
) -> dict:

    return {
        "kind": "network",
        "title": "Cannot reach provider",
        "scope": "provider",
        "status": 0,
        "msg": str(exc)[:500],
        "hint": (
            f"The backend could not connect to "
            f"{urlparse(base).netloc}. "
            "Check DNS, TLS, firewall and provider availability."
        ),
    }


def fail(info: dict) -> JSONResponse:
    return JSONResponse(
        {"error": info},
        status_code=502,
    )


# ============================================================
# MODELS
# ============================================================


class LoginIn(BaseModel):
    username: str
    password: str


class AccountIn(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=64,
    )

    password: str = Field(
        min_length=8,
        max_length=256,
    )


class ProviderIn(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=100,
    )

    base_url: str

    api_key: str = ""

    models: list[str] = Field(
        min_length=1,
        max_length=200,
    )

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value):
        return clean_url(value)


class ModelsIn(BaseModel):
    base_url: str
    api_key: str = ""

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value):
        return clean_url(value)


class ChatIn(BaseModel):
    provider_id: str
    model: str = Field(
        min_length=1,
        max_length=200,
    )
    messages: list[dict]
    temperature: float | None = None


# ============================================================
# PROVIDERS
# ============================================================


def public(provider: dict) -> dict:
    return {
        "id": provider["id"],
        "name": provider["name"],
        "base_url": provider["base_url"],
        "models": provider["models"],
        "has_key": bool(provider["api_key"]),
    }


def find(provider_id: str) -> dict:
    provider = next(
        (
            p
            for p in DB["providers"]
            if p["id"] == provider_id
        ),
        None,
    )

    if not provider:
        raise HTTPException(
            404,
            "Unknown provider",
        )

    return provider


# ============================================================
# AUTH ROUTES
# ============================================================


@app.post("/api/login")
def login(
    body: LoginIn,
    request: Request,
):

    ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    now = time.time()

    attempts, first = FAILS.get(
        ip,
        [0, now],
    )

    if now - first > 600:
        attempts = 0
        first = now

    if attempts >= 8:
        raise HTTPException(
            429,
            "Too many attempts. Try again later.",
        )

    user = DB["user"]

    valid = (
        body.username.strip().lower()
        == user["username"]
        and hmac.compare_digest(
            _hash(
                body.password,
                user["salt"],
            ),
            user["hash"],
        )
    )

    if not valid:
        FAILS[ip] = [
            attempts + 1,
            first,
        ]

        raise HTTPException(
            401,
            "Wrong username or password",
        )

    FAILS.pop(ip, None)

    response = JSONResponse(
        {
            "username": user["username"],
        }
    )

    set_cookie(
        response,
        request,
        user["username"],
    )

    return response


@app.post("/api/logout")
def logout():
    response = JSONResponse(
        {"ok": True}
    )

    response.delete_cookie(
        "modleo",
        path="/",
    )

    return response


@app.get("/api/me")
def me(
    user: str = Depends(require_user),
):
    return {
        "username": user,
    }


@app.post("/api/account")
def account(
    body: AccountIn,
    request: Request,
    user: str = Depends(require_user),
):

    DB["user"] = _new_user(
        body.username.strip(),
        body.password,
    )

    save(DB)

    response = JSONResponse(
        {
            "username": DB["user"]["username"],
        }
    )

    set_cookie(
        response,
        request,
        DB["user"]["username"],
    )

    return response


# ============================================================
# PROVIDER ROUTES
# ============================================================


@app.get("/api/providers")
def providers(
    user: str = Depends(require_user),
):
    return [
        public(provider)
        for provider in DB["providers"]
    ]


@app.post("/api/providers")
def add_provider(
    body: ProviderIn,
    user: str = Depends(require_user),
):

    base_url = clean_url(
        body.base_url
    )

    validate_provider_host(
        base_url
    )

    provider = {
        "id": secrets.token_hex(4),
        "name": body.name.strip(),
        "base_url": base_url,
        "api_key": body.api_key.strip(),
        "models": [
            model.strip()
            for model in body.models
            if model.strip()
        ],
    }

    DB["providers"].append(provider)

    save(DB)

    return public(provider)


@app.delete("/api/providers/{provider_id}")
def delete_provider(
    provider_id: str,
    user: str = Depends(require_user),
):

    original = len(DB["providers"])

    DB["providers"] = [
        provider
        for provider in DB["providers"]
        if provider["id"] != provider_id
    ]

    if len(DB["providers"]) == original:
        raise HTTPException(
            404,
            "Unknown provider",
        )

    save(DB)

    return {
        "ok": True,
    }


# ============================================================
# FETCH MODELS
# ============================================================


@app.post("/api/models")
async def fetch_models(
    body: ModelsIn,
    user: str = Depends(require_user),
):

    base = clean_url(
        body.base_url
    )

    validate_provider_host(base)

    try:

        async with create_client() as client:

            response = await client.get(
                f"{base}/models",
                headers=headers_for(
                    body.api_key.strip()
                ),
            )

    except httpx.RequestError as exc:

        return fail(
            net_error(
                exc,
                base,
            )
        )

    if response.status_code >= 400:

        return fail(
            explain(
                response.status_code,
                response.text,
                response.headers,
            )
        )

    try:

        data = response.json()

        items = (
            data.get("data")
            or data.get("models")
            or []
        )

        models = []

        for item in items:

            if isinstance(item, str):
                model_id = item

            elif isinstance(item, dict):
                model_id = (
                    item.get("id")
                    or item.get("name")
                    or ""
                )

            else:
                continue

            model_id = str(
                model_id
            ).removeprefix("models/")

            if model_id:
                models.append(model_id)

        return {
            "models": models,
        }

    except Exception:

        return fail(
            explain(
                response.status_code,
                response.text,
                response.headers,
            )
        )


# ============================================================
# PROVIDER TEST
# ============================================================


@app.post("/api/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    user: str = Depends(require_user),
):

    provider = find(
        provider_id
    )

    if not provider["models"]:
        return {
            "ok": False,
            "error": {
                "kind": "model",
                "title": "No model configured",
                "hint": "Add at least one model.",
                "scope": "model",
                "status": 0,
                "msg": "",
            },
        }

    base = provider["base_url"]

    try:

        validate_provider_host(
            base
        )

        async with create_client() as client:

            response = await client.post(
                f"{base}/chat/completions",
                headers=headers_for(
                    provider["api_key"]
                ),
                json={
                    "model": provider["models"][0],
                    "messages": [
                        {
                            "role": "user",
                            "content": "hi",
                        }
                    ],
                    "max_tokens": 1,
                    "stream": False,
                },
            )

    except httpx.RequestError as exc:

        return {
            "ok": False,
            "error": net_error(
                exc,
                base,
            ),
        }

    if response.status_code >= 400:

        return {
            "ok": False,
            "error": explain(
                response.status_code,
                response.text,
                response.headers,
            ),
        }

    return {
        "ok": True,
    }


# ============================================================
# CHAT / STREAMING
# ============================================================


@app.post("/api/chat")
async def chat(
    body: ChatIn,
    user: str = Depends(require_user),
):

    provider = find(
        body.provider_id
    )

    validate_provider_host(
        provider["base_url"]
    )

    payload = {
        "model": body.model,
        "messages": body.messages,
        "stream": True,
    }

    if body.temperature is not None:
        payload["temperature"] = body.temperature

    client = create_client()

    try:

        request = client.build_request(
            "POST",
            f"{provider['base_url']}/chat/completions",
            headers=headers_for(
                provider["api_key"]
            ),
            json=payload,
        )

        response = await client.send(
            request,
            stream=True,
        )

    except httpx.RequestError as exc:

        await client.aclose()

        return fail(
            net_error(
                exc,
                provider["base_url"],
            )
        )

    # --------------------------------------------------------
    # Provider error
    # --------------------------------------------------------

    if response.status_code >= 400:

        try:
            text = await response.aread()

            text = text.decode(
                "utf-8",
                "replace",
            )

        finally:

            await response.aclose()
            await client.aclose()

        return fail(
            explain(
                response.status_code,
                text,
                response.headers,
            )
        )

    # --------------------------------------------------------
    # Provider ignored streaming
    # --------------------------------------------------------

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if "application/json" in content_type:

        try:

            data = await response.aread()

        finally:

            await response.aclose()
            await client.aclose()

        return StreamingResponse(
            iter(
                [
                    b"data: "
                    + data
                    + b"\n\n"
                    + b"data: [DONE]\n\n"
                ]
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # --------------------------------------------------------
    # Streaming response
    # --------------------------------------------------------

    async def generate():

        try:

            async for chunk in response.aiter_raw():

                if chunk:
                    yield chunk

        except httpx.StreamError:
            # Client disconnected or upstream stream failed.
            return

        finally:

            await response.aclose()
            await client.aclose()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================
# HEALTH
# ============================================================


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "service": "modleo",
    }


@app.get("/api/debug/ip")
async def debug_ip(
    user: str = Depends(require_user),
):

    """
    Shows the public IP used by this backend.

    Useful for diagnosing provider firewall blocks.
    """

    try:

        async with create_client() as client:

            response = await client.get(
                "https://api.ipify.org?format=json"
            )

            response.raise_for_status()

            return {
                "backend_public_ip": response.json().get(
                    "ip"
                )
            }

    except Exception as exc:

        return {
            "error": str(exc)
        }


# ============================================================
# FRONTEND
# ============================================================


@app.get("/")
def index():

    frontend = (
        Path(__file__).parent
        / "static"
        / "index.html"
    )

    if not frontend.exists():

        raise HTTPException(
            404,
            "Frontend not found: static/index.html",
        )

    return FileResponse(
        frontend
    )
