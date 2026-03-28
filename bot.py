import asyncio
import ipaddress
import json
import logging
import os
import socket
from typing import Any

import httpx
from aiohttp import web
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

URL, METHOD, AUTH, BODY = range(4)

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
MAX_RESPONSE_CHARS = 4000


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


def parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
        else:
            headers["x-api-key"] = line.strip()
    return headers


def truncate(text: str, limit: int = MAX_RESPONSE_CHARS) -> str:
    if len(text) <= limit:
        return text
    notice = f"\n\n... [truncated at {limit} chars]"
    return text[: limit - len(notice)] + notice


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text(
        "🔧 *API Request Builder*\n\n"
        "Step 1/4 — Send me the full request URL.\n"
        "Example: `https://api.example.com/v1/data`\n\n"
        "Use /cancel at any time to abort.",
        parse_mode="Markdown",
    )
    return URL


async def receive_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    url = update.message.text.strip()

    safe, reason = is_ssrf_safe(url)
    if not safe:
        await update.message.reply_text(
            f"🚫 *SSRF check failed*\n`{reason}`\n\nSend a different URL or /cancel.",
            parse_mode="Markdown",
        )
        return URL

    context.user_data["url"] = url
    method_list = " | ".join(ALLOWED_METHODS)
    await update.message.reply_text(
        f"✅ URL accepted.\n\nStep 2/4 — HTTP method?\n`{method_list}`",
        parse_mode="Markdown",
    )
    return METHOD


async def receive_method(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    method = update.message.text.strip().upper()

    if method not in ALLOWED_METHODS:
        await update.message.reply_text(
            f"❌ Invalid method `{method}`.\nChoose from: `{' | '.join(ALLOWED_METHODS)}`",
            parse_mode="Markdown",
        )
        return METHOD

    context.user_data["method"] = method
    await update.message.reply_text(
        "Step 3/4 — Headers / API key (optional).\n\n"
        "Format: `Header-Name: value` (one per line)\n"
        "Or paste a bare API key → saved as `x-api-key`.\n\n"
        "Send `none` to skip.",
        parse_mode="Markdown",
    )
    return AUTH


async def receive_auth(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    raw = update.message.text.strip()
    context.user_data["headers"] = {} if raw.lower() == "none" else parse_headers(raw)

    method = context.user_data["method"]
    if method in ("GET", "HEAD", "OPTIONS", "DELETE"):
        await update.message.reply_text(
            f"⚡ No body needed for `{method}`. Executing request…",
            parse_mode="Markdown",
        )
        return await execute_request(update, context)

    await update.message.reply_text(
        "Step 4/4 — JSON body.\n\n"
        "Paste a valid JSON object or send `none` to skip.",
        parse_mode="Markdown",
    )
    return BODY


async def receive_body(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    raw = update.message.text.strip()

    if raw.lower() == "none":
        context.user_data["body"] = None
    else:
        try:
            context.user_data["body"] = json.loads(raw)
        except json.JSONDecodeError as exc:
            await update.message.reply_text(
                f"❌ *Invalid JSON*\n`{exc}`\n\nFix it and re-send, or /cancel.",
                parse_mode="Markdown",
            )
            return BODY

    await update.message.reply_text("⚡ Executing request…")
    return await execute_request(update, context)


async def execute_request(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    url: str = context.user_data["url"]
    method: str = context.user_data["method"]
    headers: dict[str, str] = context.user_data.get("headers", {})
    body: Any = context.user_data.get("body")

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=body,
            )

        resp_headers = "\n".join(f"  {k}: {v}" for k, v in response.headers.items())
        try:
            body_text = response.json()
            body_out = json.dumps(body_text, indent=2, ensure_ascii=False)
        except Exception:
            body_out = response.text

        raw_output = (
            f"📡 Response\n"
            f"Status : {response.status_code} {response.reason_phrase}\n"
            f"Headers:\n{resp_headers}\n\n"
            f"Body:\n{body_out}"
        )

    except httpx.TimeoutException:
        raw_output = f"⏱ Request timed out after {REQUEST_TIMEOUT}s. The endpoint did not respond."
    except httpx.TooManyRedirects:
        raw_output = "🔄 Request aborted: too many redirects detected."
    except httpx.RequestError as exc:
        raw_output = f"🔌 Network error: {type(exc).__name__}: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error during request execution")
        raw_output = f"💥 Unexpected error: {type(exc).__name__}: {exc}"
    finally:
        context.user_data.clear()

    await update.message.reply_text(
        f"```\n{truncate(raw_output)}\n```",
        parse_mode="Markdown",
    )
    return ConversationHandler.END


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text(
        "🛑 Request cancelled. All state cleared.\nUse /start to begin a new request."
    )
    return ConversationHandler.END


async def fallback_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Unknown command. Use /start to begin or /cancel to abort an active session."
    )


def build_application() -> Application:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise EnvironmentError("TELEGRAM_BOT_TOKEN is not set in the environment.")

    app = Application.builder().token(token).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_url)],
            METHOD: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_method)],
            AUTH: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_auth)],
            BODY: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_body)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_user=True,
        per_chat=True,
        allow_reentry=True,
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(MessageHandler(filters.COMMAND, fallback_unknown))

    return app


async def health(request: web.Request) -> web.Response:
    return web.Response(text="OK")


if __name__ == "__main__":
    application = build_application()
    logger.info("Bot is running. Press Ctrl+C to stop.")

    async def main():
        port = int(os.getenv("PORT", 8080))
        aio_app = web.Application()
        aio_app.router.add_get("/", health)
        runner = web.AppRunner(aio_app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        logger.info(f"Health server listening on port {port}")

        async with application:
            await application.initialize()
            await application.updater.start_polling(
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=True,
            )
            await application.start()
            await asyncio.Event().wait()

    asyncio.run(main())
