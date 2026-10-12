"""Automatic webpage evidence captured in isolated, short-lived browser contexts."""
import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
import os
from pathlib import Path
import re
import socket
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/screenshots", tags=["screenshots"])
SCREENSHOT_DIR = Path(os.environ.get("DANGLESCAN_SCREENSHOT_DIR", Path(__file__).parent / "data" / "screenshots"))
_slots = asyncio.Semaphore(2)


async def public_url(url):
    """Keep the capture browser away from local/private addresses and non-web URLs."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        addresses = await asyncio.wait_for(asyncio.to_thread(
            socket.getaddrinfo, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM), timeout=3)
        return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)
    except (ValueError, OSError, asyncio.TimeoutError):
        return False


async def capture_page(domain, dns_info):
    if dns_info.get("nxdomain") or not dns_info.get("resolves"):
        return {"status": "skipped", "reason": "No webpage to capture: DNS did not resolve."}
    async with _slots:
        try:
            return await asyncio.wait_for(_capture(domain), timeout=35)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            return {"status": "unavailable", "reason": "Webpage capture exceeded the 35-second limit."}
        except ImportError:
            return {"status": "unavailable", "reason": "Screenshot engine is not installed. Install requirements and run python -m playwright install chromium."}
        except Exception:
            logging.getLogger(__name__).exception("Webpage capture failed for %s", domain)
            return {"status": "unavailable", "reason": "Screenshot browser could not start or capture this page. Check Chromium installation and backend logs."}


async def _capture(domain):
    from playwright.async_api import async_playwright, Error, TimeoutError as BrowserTimeout
    browser = None
    async with async_playwright() as runtime:
        try:
            browser = await runtime.chromium.launch(headless=True, chromium_sandbox=True)
            context = await browser.new_context(viewport={"width": 1440, "height": 900},
                                                device_scale_factor=1, accept_downloads=False,
                                                service_workers="block")
            allowed = {}
            async def guard(route):
                url = route.request.url
                parsed = urlsplit(url)
                key = (parsed.scheme, parsed.netloc)
                if key not in allowed:
                    allowed[key] = await public_url(url)
                if allowed[key]:
                    await route.continue_()
                else:
                    await route.abort()
            await context.route("**/*", guard)
            # Websocket connections are unnecessary for a static evidence image.
            await context.route_web_socket("**/*", lambda ws: ws.close())
            page = await context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            async def close_popup(popup):
                if popup != page:
                    await popup.close()
            context.on("page", close_popup)
            errors = []
            for scheme in ("https", "http"):
                target = f"{scheme}://{domain}/"
                if not await public_url(target):
                    return {"status": "skipped", "reason": "Webpage capture requires a publicly resolving HTTP or HTTPS address."}
                try:
                    response = await page.goto(target, wait_until="commit", timeout=10000)
                    if response is None:
                        raise Error("No webpage response")
                    partial = False
                    try:
                        await page.wait_for_load_state("load", timeout=4000)
                    except BrowserTimeout:
                        partial = True
                    await page.wait_for_timeout(700)
                    if not await public_url(page.url):
                        raise Error("Page navigated to an unsupported address")
                    # Buffer first, so interrupted captures never leave a partial image file.
                    png = await page.screenshot(type="png", full_page=False, timeout=5000)
                    name = uuid4().hex + ".png"
                    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
                    (SCREENSHOT_DIR / name).write_bytes(png)
                    return {"status": "captured", "path": f"/screenshots/{name}",
                            "url": page.url, "captured_at": datetime.now(timezone.utc).isoformat(),
                            "http_status": response.status, "width": 1440, "height": 900,
                            "partial": partial, "https_fallback": scheme == "http"}
                except Error as exc:
                    message = str(exc).split("Call log:")[0].strip()
                    errors.append(f"{scheme.upper()}: {message[:180]}")
            return {"status": "unavailable", "reason": "No webpage could be captured. " + " | ".join(errors)}
        finally:
            if browser is not None:
                await browser.close()


@router.get("/{filename}")
def screenshot_image(filename: str):
    if not re.fullmatch(r"[a-f0-9]{32}\.png", filename):
        raise HTTPException(404, "Screenshot not found")
    path = SCREENSHOT_DIR / filename
    if not path.is_file():
        raise HTTPException(404, "Screenshot no longer available")
    return FileResponse(path, media_type="image/png", headers={"X-Content-Type-Options": "nosniff"})
