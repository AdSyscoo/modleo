"""Modleo backend: Chat UI -> FastAPI -> third-party LLM API.
Run:  pip install -r requirements.txt && uvicorn main:app --port 8000
"""
import base64, hashlib, hmac, json, os, re, secrets, time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

DATA = Path(os.getenv("DATA_DIR", "data")); DATA.mkdir(parents=True, exist_ok=True)
STORE = DATA / "store.json"
UA = os.getenv("UPSTREAM_UA", "curl/8.5.0")
app = FastAPI(title="Modleo", docs_url=None, redoc_url=None)

# ---------------- storage ----------------
def _hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def _new_user(username: str, password: str) -> dict:
    salt = secrets.token_hex(8)
    return {"username": username.lower(), "salt": salt, "hash": _hash(password, salt)}

def load() -> dict:
    if STORE.exists():
        return json.loads(STORE.read_text())
    db = {"secret": secrets.token_hex(32), "providers": [],
          "user": _new_user(os.getenv("ADMIN_USER", "demouser1"), os.getenv("ADMIN_PASSWORD", "Demopass@123"))}
    seed = os.getenv("PROVIDERS_JSON")
    if seed:
        for p in json.loads(seed):
            db["providers"].append({"id": secrets.token_hex(4), "name": p["name"], "base_url": p["base_url"].rstrip("/"),
                                    "api_key": p.get("api_key", ""), "models": p.get("models", [])})
    save(db); return db

def save(db: dict) -> None:
    tmp = STORE.with_suffix(".tmp"); tmp.write_text(json.dumps(db, indent=2)); tmp.replace(STORE)

DB = load()
SECRET = (os.getenv("SECRET_KEY") or DB["secret"]).encode()

# ---------------- auth (signed cookie) ----------------
def _sign(p: str) -> str: return hmac.new(SECRET, p.encode(), hashlib.sha256).hexdigest()

def make_token(user: str) -> str:
    p = f"{user}|{int(time.time()) + 7 * 86400}"
    return base64.urlsafe_b64encode(p.encode()).decode() + "." + _sign(p)

def read_token(t: str | None):
    try:
        b, sig = t.rsplit(".", 1); p = base64.urlsafe_b64decode(b.encode()).decode()
        if not hmac.compare_digest(sig, _sign(p)): return None
        u, exp = p.rsplit("|", 1)
        return u if int(exp) > time.time() else None
    except Exception:
        return None

def set_cookie(resp: Response, req: Request, user: str):
    secure = req.headers.get("x-forwarded-proto", req.url.scheme) == "https"
    resp.set_cookie("modleo", make_token(user), httponly=True, samesite="lax", secure=secure, max_age=7 * 86400)

def require_user(request: Request) -> str:
    u = read_token(request.cookies.get("modleo"))
    if not u: raise HTTPException(401, "Not signed in")
    return u

FAILS: dict[str, list] = {}

# ---------------- error explanations ----------------
def explain(status: int, text: str) -> dict:
    msg = text
    try:
        j = json.loads(text); e = j.get("error")
        msg = (e.get("message") if isinstance(e, dict) else e) or j.get("message") or text
    except Exception:
        pass
    msg = str(msg); low = (msg + " " + text).lower()
    def R(kind, title, hint, scope, m=None):
        return {"kind": kind, "title": title, "hint": hint, "scope": scope, "status": status, "msg": (msg if m is None else m)[:300]}
    if text.lstrip()[:1] == "<":
        t = re.search(r"<title>([^<]*)", text, re.I); c = re.search(r"error code:?\s*(\d{4})", text, re.I)
        ip = re.search(r"Your IP:[\s\S]{0,120}?((?:\d{1,3}\.){3}\d{1,3})", text, re.I)
        extra = " · ".join(x for x in [t and t.group(1).strip(), c and "Error " + c.group(1), ip and "Blocked IP " + ip.group(1)] if x)
        return R("block", "Blocked by the provider firewall",
                 "The gateway returned a block page. Its firewall rejects requests from this server's network. Run Modleo from a different network, use another gateway, or ask the provider to allow API traffic.", "provider", extra)
    if re.search(r"quota|insufficient|额度|credit|balance|billing|余额|arrear", low) or status == 402:
        return R("quota", "Out of credits", "This provider account has no balance left. Top up or claim free credits on the provider site, or switch provider.", "provider")
    if status == 401 or re.search(r"invalid token|invalid api key|incorrect api key|unauthorized", low):
        return R("auth", "API key rejected", "Update the key in Providers & keys. Check for extra spaces.", "provider")
    if status == 404 or re.search(r"model.*(not found|does not exist|not available)|no available channel|无可用渠道", low):
        return R("model", "Model not available", "Your key may not have access to this model. Pick one from the Fetch models list.", "model")
    if status == 403: return R("denied", "Access denied", "The provider refused the request. Check your key, plan and allowed models.", "provider")
    if status == 429 or re.search(r"rate limit|too many", low): return R("rate", "Rate limited", "Too many requests. Wait a minute or switch model or provider.", "retry")
    if status >= 500: return R("server", "Provider error", "A temporary problem on the provider side. Try again or switch.", "retry")
    return R("other", f"Request failed (HTTP {status})", "", "none")

def net_error(e: Exception, base: str) -> dict:
    return {"kind": "net", "title": "Cannot reach the provider", "scope": "provider", "status": 0, "msg": str(e)[:200],
            "hint": f"The server could not connect to {urlparse(base).netloc}. Check the base URL."}

def fail(info: dict) -> JSONResponse:  # upstream problems are 502 so 401 always means "session expired"
    return JSONResponse({"error": info}, status_code=502)

# ---------------- models ----------------
class LoginIn(BaseModel): username: str; password: str
class AccountIn(BaseModel): username: str = Field(min_length=3); password: str = Field(min_length=6)
class ProviderIn(BaseModel): name: str = Field(min_length=1); base_url: str; api_key: str = ""; models: list[str] = Field(min_length=1)
class ModelsIn(BaseModel): base_url: str; api_key: str = ""
class ChatIn(BaseModel): provider_id: str; model: str; messages: list[dict]; temperature: float | None = None

def headers_for(key: str) -> dict:
    h = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "*/*"}
    if key: h["Authorization"] = "Bearer " + key
    return h

def public(p: dict) -> dict:
    return {"id": p["id"], "name": p["name"], "base_url": p["base_url"], "models": p["models"], "has_key": bool(p["api_key"])}

def find(pid: str) -> dict:
    p = next((x for x in DB["providers"] if x["id"] == pid), None)
    if not p: raise HTTPException(404, "Unknown provider")
    return p

def clean_url(u: str) -> str:
    u = u.strip().rstrip("/")
    if urlparse(u).scheme not in ("http", "https") or not urlparse(u).netloc: raise HTTPException(400, "Base URL must start with http:// or https://")
    return u

# ---------------- routes: auth ----------------
@app.post("/api/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "?"; now = time.time()
    n, first = FAILS.get(ip, [0, now])
    if now - first > 600: n, first = 0, now
    if n >= 8: raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    u = DB["user"]
    ok = body.username.strip().lower() == u["username"] and hmac.compare_digest(_hash(body.password, u["salt"]), u["hash"])
    if not ok:
        FAILS[ip] = [n + 1, first]; raise HTTPException(401, "Wrong username or password")
    FAILS.pop(ip, None)
    resp = JSONResponse({"username": u["username"]}); set_cookie(resp, request, u["username"]); return resp

@app.post("/api/logout")
def logout():
    resp = JSONResponse({"ok": True}); resp.delete_cookie("modleo"); return resp

@app.get("/api/me")
def me(user: str = Depends(require_user)): return {"username": user}

@app.post("/api/account")
def account(body: AccountIn, request: Request, user: str = Depends(require_user)):
    DB["user"] = _new_user(body.username.strip(), body.password); save(DB)
    resp = JSONResponse({"username": DB["user"]["username"]}); set_cookie(resp, request, DB["user"]["username"]); return resp

# ---------------- routes: providers ----------------
@app.get("/api/providers")
def providers(user: str = Depends(require_user)): return [public(p) for p in DB["providers"]]

@app.post("/api/providers")
def add_provider(body: ProviderIn, user: str = Depends(require_user)):
    p = {"id": secrets.token_hex(4), "name": body.name.strip(), "base_url": clean_url(body.base_url),
         "api_key": body.api_key.strip(), "models": [m.strip() for m in body.models if m.strip()]}
    DB["providers"].append(p); save(DB); return public(p)

@app.delete("/api/providers/{pid}")
def del_provider(pid: str, user: str = Depends(require_user)):
    DB["providers"] = [p for p in DB["providers"] if p["id"] != pid]; save(DB); return {"ok": True}

@app.post("/api/models")
async def fetch_models(body: ModelsIn, user: str = Depends(require_user)):
    base = clean_url(body.base_url)
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(base + "/models", headers=headers_for(body.api_key.strip()))
    except httpx.RequestError as e:
        return fail(net_error(e, base))
    if r.status_code >= 400: return fail(explain(r.status_code, r.text))
    try:
        j = r.json(); items = j.get("data") or j.get("models") or []
        return {"models": [str(m.get("id") or m.get("name", "")).removeprefix("models/") for m in items if m.get("id") or m.get("name")]}
    except Exception:
        return fail(explain(200, r.text))

@app.post("/api/providers/{pid}/test")
async def test_provider(pid: str, user: str = Depends(require_user)):
    p = find(pid)
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(p["base_url"] + "/chat/completions", headers=headers_for(p["api_key"]),
                             json={"model": p["models"][0], "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1})
    except httpx.RequestError as e:
        return {"ok": False, "error": net_error(e, p["base_url"])}
    return {"ok": True} if r.status_code < 400 else {"ok": False, "error": explain(r.status_code, r.text)}

# ---------------- routes: chat (the core flow) ----------------
@app.post("/api/chat")
async def chat(body: ChatIn, user: str = Depends(require_user)):
    p = find(body.provider_id)
    payload = {"model": body.model, "messages": body.messages, "stream": True}
    if body.temperature is not None: payload["temperature"] = body.temperature
    client = httpx.AsyncClient(timeout=httpx.Timeout(180, connect=20))
    try:
        r = await client.send(client.build_request("POST", p["base_url"] + "/chat/completions", headers=headers_for(p["api_key"]), json=payload), stream=True)
    except httpx.RequestError as e:
        await client.aclose(); return fail(net_error(e, p["base_url"]))
    if r.status_code >= 400:
        text = (await r.aread()).decode("utf-8", "replace"); await r.aclose(); await client.aclose()
        return fail(explain(r.status_code, text))
    if "application/json" in r.headers.get("content-type", ""):  # provider ignored stream=true
        data = await r.aread(); await r.aclose(); await client.aclose()
        return StreamingResponse(iter([b"data: " + data + b"\n\ndata: [DONE]\n\n"]), media_type="text/event-stream")
    async def gen():
        try:
            async for chunk in r.aiter_raw(): yield chunk
        finally:
            await r.aclose(); await client.aclose()
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ---------------- frontend ----------------
@app.get("/healthz")
def healthz(): return {"ok": True}

@app.get("/")
def index(): return FileResponse(Path(__file__).parent / "static" / "index.html")
