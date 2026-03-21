import time
import os
from typing import Any
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(title="FastAPI Backend", docs_url=None, redoc_url=None)
START = time.monotonic()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"[fastapi] {request.method} {request.url.path}", flush=True)
    return await call_next(request)


# API — echo back request details
@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_handler(path: str, request: Request) -> dict[str, Any]:
    body: Any = None
    raw = await request.body()
    if raw:
        try:
            import json
            body = json.loads(raw)
        except Exception:
            body = raw.decode(errors="replace")

    return {
        "backend": "fastapi",
        "method": request.method,
        "path": f"/api/{path}",
        "query": dict(request.query_params),
        "body": body,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Auth endpoint
@app.post("/auth/login")
async def auth_login(request: Request) -> dict[str, Any]:
    import json
    raw = await request.body()
    body = json.loads(raw) if raw else {}
    username = body.get("username", "anonymous")
    return {"backend": "fastapi", "token": f"fake-jwt-for-{username}", "expiresIn": 3600}


@app.put("/auth/refresh")
async def auth_refresh() -> dict[str, Any]:
    return {"backend": "fastapi", "token": "refreshed-token", "expiresIn": 3600}


# Webhook endpoint
@app.post("/webhook/{path:path}")
async def webhook(path: str, request: Request) -> dict[str, Any]:
    import json
    raw = await request.body()
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        payload = {}
    print(f"[fastapi] webhook: {payload}", flush=True)
    return {"backend": "fastapi", "received": True, "path": f"/webhook/{path}"}


# Health
@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "backend": "fastapi", "uptime": round(time.monotonic() - START, 2)}


# Static (plain proxy)
@app.get("/static/{path:path}")
async def static(path: str) -> PlainTextResponse:
    return PlainTextResponse(f"Static: /static/{path}")


# Home page
@app.get("/")
async def home() -> HTMLResponse:
    return HTMLResponse("<html><body><h1>FastAPI Backend</h1><p>Encrypt Proxy test backend</p></body></html>")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8090"))
    uvicorn.run(app, host="0.0.0.0", port=port)
