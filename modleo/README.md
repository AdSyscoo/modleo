# Modleo - Chat UI -> FastAPI backend -> third-party LLM API

    Browser (Chat UI)  -->  FastAPI backend (this project)  -->  Provider / gateway API
                            keys stored here, never in the browser

## Run locally
    pip install -r requirements.txt
    python -m uvicorn main:app --port 8000

Open http://localhost:8000. First login: `demouser1` / `Demopass@123`
(change it in Providers & keys -> Account, or set ADMIN_USER / ADMIN_PASSWORD before the first start).

## Deploy (any host that runs Python or Docker)
- Docker: `docker build -t modleo . && docker run -p 8000:8000 -v modleo-data:/data modleo`
- Render / Railway / Fly.io: point at this folder; start command
  `python -m uvicorn main:app --host 0.0.0.0 --port $PORT`.
  If the host's disk resets on redeploy, attach a persistent volume at DATA_DIR, or seed providers with
  the PROVIDERS_JSON variable (see .env.example).
- Serve over HTTPS and set a strong SECRET_KEY.

## Notes
- Provider keys live in DATA_DIR/store.json on the server. Protect that disk.
- A gateway whose firewall blocks your server's network (for example Cloudflare "Attention Required") must be
  reached from a different network, such as your own computer. Modleo shows the block page's error code and IP.
