import asyncio
import base64
import ipaddress
import json
import logging
import os
import socket
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# --- Config ---
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
REQUEST_TIMEOUT = 10.0


# --- Rate limiter ---
class RateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._store: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        timestamps = self._store.get(key, [])
        timestamps = [t for t in timestamps if now - t < self.window]

        if len(timestamps) >= self.max_requests:
            self._store[key] = timestamps
            return False

        timestamps.append(now)
        self._store[key] = timestamps
        return True


rate_limiter = RateLimiter(max_requests=20, window_seconds=60)


# --- Models ---
class ProxyRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = Field(default=None)


# --- SSRF Guard ---
def is_ssrf_safe(url: str) -> tuple[bool, str]:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Only http and https schemes are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "Could not extract hostname from URL."

        try:
            resolved_addrs = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            return False, f"DNS resolution failed: {exc}"

        for addr_info in resolved_addrs:
            raw_ip = addr_info[4][0]
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                return False, f"Invalid IP address resolved: {raw_ip}"

            for blocked in BLOCKED_NETWORKS:
                if ip in blocked:
                    return (
                        False,
                        f"Resolved IP {ip} is within a blocked range ({blocked}). Request denied.",
                    )

        return True, ""

    except Exception as exc:
        return False, f"URL validation error: {exc}"


# --- App ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Proxy API starting up...")
    yield
    logger.info("Proxy API shutting down...")


app = FastAPI(title="Proxy API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def health():
    return {"status": "ok", "region": os.getenv("RENDER_REGION", "unknown")}


@app.post("/")
async def proxy(
    request: Request,
    url: Optional[str] = Query(default=None),
):
    # 1. Rate limiting by IP
    client_ip = request.headers.get("x-forwarded-for")
    if not client_ip:
        client_ip = request.client.host if request.client and request.client.host else "unknown"
    client_ip = client_ip.split(",")[0].strip()
    logger.info("[proxy] client_ip=%s", client_ip)

    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: 20 RPM")

    content_type = request.headers.get("content-type", "")
    is_multipart = "multipart/form-data" in content_type
    logger.info("[proxy] content_type=%r is_multipart=%s", content_type, is_multipart)

    # 2. Resolve target URL and method
    if is_multipart:
        target_url = url
        if not target_url:
            raise HTTPException(status_code=400, detail="Multipart requests must supply ?url= query param")
        method = "POST"
        payload = None
        logger.info("[proxy] multipart mode target_url=%s", target_url)
    else:
        try:
            raw = await request.body()
            logger.info("[proxy] raw body length=%d", len(raw))
            data = json.loads(raw)
            payload = ProxyRequest(**data)
        except Exception as exc:
            logger.error("[proxy] failed to parse JSON body: %s", exc)
            raise HTTPException(status_code=422, detail=f"Failed to parse JSON body: {exc}")
        target_url = payload.url
        method = payload.method.upper()
        logger.info("[proxy] json mode target_url=%s method=%s", target_url, method)

    # 3. SSRF check
    logger.info("[proxy] running SSRF check for %s", target_url)
    safe, reason = await asyncio.to_thread(is_ssrf_safe, target_url)
    if not safe:
        logger.warning("[proxy] SSRF blocked: %s", reason)
        raise HTTPException(status_code=400, detail=f"SSRF check failed: {reason}")

    # 4. Method validation
    if method not in ALLOWED_METHODS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid method. Allowed: {', '.join(sorted(ALLOWED_METHODS))}",
        )

    # 5. Execute upstream request
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
            if is_multipart:
                raw_body = await request.body()
                logger.info("[proxy] forwarding multipart body bytes=%d", len(raw_body))
                response = await client.post(
                    target_url,
                    content=raw_body,
                    headers={"Content-Type": content_type},
                )
            else:
                req_kwargs: dict = {
                    "method": method,
                    "url": target_url,
                    "headers": payload.headers,
                }
                if payload.body is not None and method not in ("GET", "HEAD", "OPTIONS", "DELETE"):
                    req_kwargs["json"] = payload.body
                response = await client.request(**req_kwargs)

        logger.info("[proxy] upstream response status=%d content_type=%s",
                    response.status_code, response.headers.get("content-type", ""))

    except httpx.TimeoutException:
        logger.error("[proxy] upstream timeout after %ss", REQUEST_TIMEOUT)
        raise HTTPException(status_code=504, detail=f"Request timed out after {REQUEST_TIMEOUT}s")
    except httpx.TooManyRedirects:
        logger.error("[proxy] too many redirects")
        raise HTTPException(status_code=400, detail="Too many redirects")
    except httpx.RequestError as exc:
        logger.error("[proxy] network error: %s %s", type(exc).__name__, exc)
        raise HTTPException(status_code=502, detail=f"Network error: {type(exc).__name__}: {exc}")
    except Exception as exc:
        logger.exception("[proxy] unexpected error")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {type(exc).__name__}: {exc}")

    # 6. Build response
    resp_content_type = response.headers.get("content-type", "")
    is_binary = any(t in resp_content_type for t in ("audio/", "video/", "image/", "application/octet-stream"))

    if is_binary:
        body_out = base64.b64encode(response.content).decode("ascii")
        encoding = "base64"
    else:
        try:
            body_out = response.json()
            encoding = "json"
        except Exception:
            body_out = response.text
            encoding = "text"

    logger.info("[proxy] response encoding=%s body_preview=%s", encoding,
                str(body_out)[:200] if not is_binary else f"<binary {len(response.content)} bytes>")

    return JSONResponse(
        status_code=response.status_code,
        content={
            "status": response.status_code,
            "reason": response.reason_phrase,
            "headers": dict(response.headers),
            "body": body_out,
            "encoding": encoding,
        },
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)