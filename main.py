from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import socket
import time
from typing import AsyncGenerator, Optional

import dns.resolver
import httpx
import openpyxl
from openai import OpenAI
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

app = FastAPI(title="Subdomain Takeover Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Known takeover fingerprints
TAKEOVER_SIGNATURES = {
    "there isn't a github pages site here": ("GitHub Pages", "critical"),
    "for root domain use an a record": ("GitHub Pages", "critical"),
    "nosuchbucket": ("AWS S3", "critical"),
    "the specified bucket does not exist": ("AWS S3", "critical"),
    "no such bucket": ("AWS S3", "critical"),
    "fastly error: unknown domain": ("Fastly", "critical"),
    "this shop is currently unavailable": ("Shopify", "high"),
    "no settings were found for this company": ("HubSpot", "high"),
    "project not found": ("Netlify", "critical"),
    "404 not found": ("Generic", "medium"),
    "domain not configured": ("Generic", "high"),
    "this domain is for sale": ("Parked", "high"),
    "this page is parked": ("Parked", "high"),
    "page not found on bitbucket": ("Bitbucket", "critical"),
    "the feed has not been found": ("Tumblr", "high"),
    "whatever you were looking for doesn't currently exist": ("Tumblr", "high"),
    "help center closed": ("Zendesk", "critical"),
    "this helpdesk site is currently unavailable": ("UserVoice", "high"),
    "mybucket.s3.amazonaws.com": ("AWS S3 CNAME", "critical"),
    ".azurewebsites.net": ("Azure", "high"),
    ".cloudfront.net": ("CloudFront", "medium"),
    "heroku | no such app": ("Heroku", "critical"),
    "no such app": ("Heroku", "critical"),
    "there's nothing here": ("Generic", "medium"),
}

CLOUD_CNAME_PATTERNS = [
    (r"\.s3\.amazonaws\.com$", "AWS S3"),
    (r"\.s3-website.*\.amazonaws\.com$", "AWS S3 Website"),
    (r"\.azurewebsites\.net$", "Azure Web Apps"),
    (r"\.azureedge\.net$", "Azure CDN"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.herokuapp\.com$", "Heroku"),
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.netlify\.app$", "Netlify"),
    (r"\.vercel\.app$", "Vercel"),
    (r"\.pantheonsite\.io$", "Pantheon"),
    (r"\.shopifypreview\.com$", "Shopify"),
    (r"\.myshopify\.com$", "Shopify"),
    (r"\.ghost\.io$", "Ghost"),
    (r"\.webflow\.io$", "Webflow"),
    (r"\.surge\.sh$", "Surge"),
    (r"\.fastly\.net$", "Fastly"),
    (r"\.zendesk\.com$", "Zendesk"),
    (r"\.hubspot\.com$", "HubSpot"),
    (r"\.helpscoutdocs\.com$", "HelpScout"),
]


def parse_domains_from_excel(content: bytes) -> list[str]:
    from io import BytesIO
    wb = openpyxl.load_workbook(BytesIO(content))
    domains = []
    for sheet in wb.worksheets:
        for row in sheet.iter_rows(values_only=True):
            for cell in row:
                if cell and isinstance(cell, str):
                    val = normalize_domain(cell)
                    if val:
                        domains.append(val)
    return list(set(domains))


def resolve_dns(domain: str) -> dict:
    result = {"has_a": False, "has_cname": False, "cname_target": None,
              "a_records": [], "resolves": False, "nxdomain": False}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        answers = resolver.resolve(domain, "CNAME")
        result["has_cname"] = True
        result["cname_target"] = str(answers[0].target).rstrip(".")
        result["resolves"] = True
    except dns.resolver.NXDOMAIN:
        result["nxdomain"] = True
        return result
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "A")
        result["has_a"] = True
        result["a_records"] = [str(r) for r in answers]
        result["resolves"] = True
    except dns.resolver.NXDOMAIN:
        result["nxdomain"] = True
    except Exception:
        pass

    return result


async def fetch_http(domain: str) -> dict:
    result = {"status": None, "title": None, "body_snippet": "", "error": None}
    for scheme in ["https", "http"]:
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                         verify=False) as client:
                resp = await client.get(f"{scheme}://{domain}",
                                        headers={"User-Agent": "Mozilla/5.0"})
                result["status"] = resp.status_code
                body = resp.text[:3000]
                result["body_snippet"] = body[:500]
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]
                return result
        except Exception as e:
            result["error"] = str(e)[:100]
    return result


def rule_based_analysis(domain: str, dns_info: dict, http_info: dict) -> dict:
    verdict = "clean"
    severity = "info"
    provider = None
    reason = "No issues detected"
    confidence = 0

    # NXDOMAIN with no resolution = dangling
    if dns_info["nxdomain"]:
        verdict = "dangling_dns"
        severity = "high"
        reason = "Domain returns NXDOMAIN — DNS record exists but target does not resolve"
        confidence = 85

    # Check CNAME points to known cloud provider
    cname = dns_info.get("cname_target", "") or ""
    for pattern, prov in CLOUD_CNAME_PATTERNS:
        if re.search(pattern, cname, re.IGNORECASE):
            provider = prov
            if not dns_info["has_a"] and not dns_info["resolves"]:
                verdict = "dangling_dns"
                severity = "critical"
                reason = f"CNAME points to {prov} ({cname}) but does not resolve — likely abandoned resource"
                confidence = 90
            break

    # Check HTTP body for takeover signatures
    body = (http_info.get("body_snippet") or "").lower()
    for sig, (prov, sev) in TAKEOVER_SIGNATURES.items():
        if sig in body:
            verdict = "takeover_vulnerable"
            severity = sev
            provider = prov
            reason = f"Page contains takeover fingerprint for {prov}: '{sig}'"
            confidence = 95
            break

    # HTTP errors on cloud-pointed domains
    if http_info.get("status") in [404, 410] and cname:
        if verdict == "clean":
            verdict = "dangling_dns"
            severity = "high"
            reason = f"CNAME to {cname} returns {http_info['status']} — resource may be deleted"
            confidence = 75

    return {
        "verdict": verdict,
        "severity": severity,
        "provider": provider,
        "reason": reason,
        "confidence": confidence,
    }


OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.2")
# Zero means no application-level deadline: passive tools run until they finish.
# Set ENUM_TIMEOUT_SECONDS to a positive value when a deployment needs a cap.
ENUM_TIMEOUT_SECONDS = int(os.getenv("ENUM_TIMEOUT_SECONDS", "0"))
CERTSPOTTER_MAX_PAGES = int(os.getenv("CERTSPOTTER_MAX_PAGES", "2"))
MAX_DISCOVERED_DOMAINS = int(os.getenv("MAX_DISCOVERED_DOMAINS", "1000"))


def openai_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    if re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain) and "." in domain:
        return domain
    return None


async def run_command_lines(
    cmd: list[str],
    timeout: int = ENUM_TIMEOUT_SECONDS,
    on_line=None,
) -> list[str]:
    if not shutil.which(cmd[0]):
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return []

    lines = []

    async def read_stdout() -> None:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            decoded = line.decode(errors="replace").strip()
            lines.append(decoded)
            if on_line is not None:
                await on_line(decoded)

    reader_task = asyncio.create_task(read_stdout())
    cancelled = False

    def kill_process_group() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            with contextlib.suppress(ProcessLookupError):
                proc.kill()

    try:
        if timeout > 0:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        else:
            await proc.wait()
    except asyncio.TimeoutError:
        kill_process_group()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=2)
    except asyncio.CancelledError:
        cancelled = True
        kill_process_group()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=2)
    finally:
        try:
            await asyncio.wait_for(reader_task, timeout=2)
        except asyncio.TimeoutError:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader_task

    if cancelled:
        raise asyncio.CancelledError

    return lines


async def enumerate_certspotter(domain: str) -> list[str]:
    """Discover certificate-backed DNS names without requiring local CLI tools."""
    discovered = set()
    after = None

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            for _ in range(CERTSPOTTER_MAX_PAGES):
                params = {
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }
                if after is not None:
                    params["after"] = after

                response = await client.get(
                    "https://api.certspotter.com/v1/issuances",
                    params=params,
                    headers={"User-Agent": "DangleScan/1.0"},
                )
                response.raise_for_status()
                issuances = response.json()
                if not issuances:
                    break

                for issuance in issuances:
                    for name in issuance.get("dns_names", []):
                        normalized = normalize_domain(name.removeprefix("*."))
                        if normalized and (
                            normalized == domain or normalized.endswith(f".{domain}")
                        ):
                            discovered.add(normalized)

                after = issuances[-1].get("id")
                if after is None or len(discovered) >= MAX_DISCOVERED_DOMAINS:
                    break
    except (httpx.HTTPError, ValueError, TypeError):
        return []

    return sorted(discovered)[:MAX_DISCOVERED_DOMAINS]


async def enumerate_hackertarget(domain: str) -> list[str]:
    """Use HackerTarget's host-search feed as a no-key passive fallback."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                headers={"User-Agent": "DangleScan/1.0"},
            )
            response.raise_for_status()
    except httpx.HTTPError:
        return []

    discovered = set()
    for line in response.text.splitlines():
        hostname = line.partition(",")[0]
        normalized = normalize_domain(hostname)
        if normalized and (
            normalized == domain or normalized.endswith(f".{domain}")
        ):
            discovered.add(normalized)
    return sorted(discovered)


async def enumerate_urlscan(domain: str) -> list[str]:
    """Collect hostnames observed by URLScan as another passive source."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": "10000"},
                headers={"User-Agent": "DangleScan/1.0"},
            )
            response.raise_for_status()
            results = response.json().get("results", [])
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return []

    discovered = set()
    for result in results:
        normalized = normalize_domain(result.get("page", {}).get("domain", ""))
        if normalized and (
            normalized == domain or normalized.endswith(f".{domain}")
        ):
            discovered.add(normalized)
    return sorted(discovered)


async def enumerate_subdomains(domain: str) -> list[str]:
    commands = [
        ["subfinder", "-silent", "-d", domain],
        ["amass", "enum", "-passive", "-d", domain],
    ]
    async def certspotter_with_timeout() -> list[str]:
        if ENUM_TIMEOUT_SECONDS <= 0:
            return await enumerate_certspotter(domain)
        try:
            return await asyncio.wait_for(enumerate_certspotter(domain), timeout=ENUM_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return []

    tasks = [
        asyncio.create_task(certspotter_with_timeout()),
        asyncio.create_task(enumerate_hackertarget(domain)),
        asyncio.create_task(enumerate_urlscan(domain)),
        *(asyncio.create_task(run_command_lines(cmd)) for cmd in commands),
    ]
    wait_timeout = ENUM_TIMEOUT_SECONDS + 3 if ENUM_TIMEOUT_SECONDS > 0 else None
    done, pending = await asyncio.wait(tasks, timeout=wait_timeout)
    for task in pending:
        task.cancel()

    results = []
    for task in done:
        if not task.cancelled() and task.exception() is None:
            results.append(task.result())
    discovered = set()
    for lines in results:
        for line in lines:
            normalized = normalize_domain(line)
            if normalized and (normalized == domain or normalized.endswith(f".{domain}")):
                discovered.add(normalized)
    return sorted(discovered)[:MAX_DISCOVERED_DOMAINS]


async def expand_domains(domains: list[str], use_enum: bool) -> list[str]:
    normalized = sorted({d for d in (normalize_domain(domain) for domain in domains) if d})
    if not use_enum:
        return normalized

    discovered = set(normalized)
    enum_tasks = [enumerate_subdomains(domain) for domain in normalized]
    for result in await asyncio.gather(*enum_tasks):
        discovered.update(result)
    return sorted(discovered)


async def ask_codex(domain: str, dns_info: dict, http_info: dict, rule_result: dict) -> str:
    if not openai_available():
        return "Codex analysis skipped: OPENAI_API_KEY is not set."

    prompt = f"""You are a security analyst reviewing a subdomain for takeover vulnerabilities.

Domain: {domain}
DNS Info: {json.dumps(dns_info)}
HTTP Status: {http_info.get('status')}
Page Title: {http_info.get('title')}
Body Snippet: {http_info.get('body_snippet', '')[:300]}
Rule Engine Finding: {json.dumps(rule_result)}

In 2-3 sentences max, give:
1. Whether this is a real risk or false positive
2. The specific action the security team should take
3. Which team likely owns this (infra/marketing/dev)

Be direct and specific. No fluff."""

    try:
        def _ask() -> str:
            client = OpenAI()
            response = client.responses.create(
                model=OPENAI_MODEL,
                instructions=(
                    "You are Codex acting as a concise application security reviewer. "
                    "Only assess the supplied DNS, HTTP, and rule-engine evidence."
                ),
                input=prompt,
            )
            return response.output_text.strip()

        return await asyncio.to_thread(_ask)
    except Exception as e:
        return f"Codex analysis unavailable: {str(e)[:120]}"


async def scan_domain(domain: str, use_ai: bool = True) -> dict:
    start = time.time()

    # DNS resolution
    dns_info = await asyncio.to_thread(resolve_dns, domain)

    # HTTP fetch (skip if NXDOMAIN)
    http_info = {"status": None, "title": None, "body_snippet": "", "error": "Skipped"}
    if not dns_info["nxdomain"] and dns_info["resolves"]:
        http_info = await fetch_http(domain)

    # Rule-based analysis
    rule_result = rule_based_analysis(domain, dns_info, http_info)

    # AI analysis only for non-clean findings
    ai_analysis = None
    if use_ai and rule_result["verdict"] != "clean":
        ai_analysis = await ask_codex(domain, dns_info, http_info, rule_result)

    elapsed = round(time.time() - start, 2)

    return {
        "domain": domain,
        "verdict": rule_result["verdict"],
        "severity": rule_result["severity"],
        "provider": rule_result["provider"],
        "reason": rule_result["reason"],
        "confidence": rule_result["confidence"],
        "ai_analysis": ai_analysis,
        "dns": {
            "resolves": dns_info["resolves"],
            "nxdomain": dns_info["nxdomain"],
            "cname": dns_info["cname_target"],
            "a_records": dns_info["a_records"],
        },
        "http": {
            "status": http_info["status"],
            "title": http_info["title"],
        },
        "scan_time_s": elapsed,
    }


async def stream_scan(domains: list[str], use_ai: bool, use_enum: bool) -> AsyncGenerator[str, None]:
    input_total = len(domains)
    yield f"data: {json.dumps({'type': 'enumerating', 'total': input_total, 'enabled': use_enum})}\n\n"
    semaphore = asyncio.Semaphore(10)  # max 10 concurrent scans

    async def scan_with_sem(domain):
        async with semaphore:
            return await scan_domain(domain, use_ai)

    normalized = sorted({d for d in (normalize_domain(domain) for domain in domains) if d})

    if not use_enum:
        total = len(normalized)
        yield f"data: {json.dumps({'type': 'start', 'total': total, 'input_total': input_total, 'discovered': 0, 'enumerating': False})}\n\n"
        tasks = [asyncio.create_task(scan_with_sem(domain)) for domain in normalized]
        completed = 0
        try:
            for task in asyncio.as_completed(tasks):
                result = await task
                completed += 1
                payload = {
                    "type": "result",
                    "completed": completed,
                    "total": total,
                    "input_total": input_total,
                    "enumerating": False,
                    "result": result,
                }
                yield f"data: {json.dumps(payload)}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'total': total, 'completed': completed, 'discovered': 0, 'enumeration_enabled': False})}\n\n"
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return

    discovery_queue = asyncio.Queue()

    async def produce(source, root_domain: str) -> None:
        try:
            names = await source
            for name in names:
                normalized_name = normalize_domain(name)
                if normalized_name and (
                    normalized_name == root_domain
                    or normalized_name.endswith(f".{root_domain}")
                ):
                    await discovery_queue.put(("domain", normalized_name))
        except Exception:
            pass
        finally:
            await discovery_queue.put(("done", None))

    async def produce_command(cmd: list[str], root_domain: str) -> None:
        async def emit(line: str) -> None:
            normalized_name = normalize_domain(line)
            if normalized_name and (
                normalized_name == root_domain
                or normalized_name.endswith(f".{root_domain}")
            ):
                await discovery_queue.put(("domain", normalized_name))

        try:
            await run_command_lines(cmd, on_line=emit)
        except Exception:
            pass
        finally:
            await discovery_queue.put(("done", None))

    producers = []
    for root_domain in normalized:
        sources = [
            enumerate_certspotter(root_domain),
            enumerate_hackertarget(root_domain),
            enumerate_urlscan(root_domain),
        ]
        producers.extend(
            asyncio.create_task(produce(source, root_domain)) for source in sources
        )
        producers.extend([
            asyncio.create_task(produce_command(
                ["subfinder", "-silent", "-d", root_domain], root_domain
            )),
            asyncio.create_task(produce_command(
                ["amass", "enum", "-passive", "-d", root_domain], root_domain
            )),
        ])

    active_producers = len(producers)
    seen = set()
    scan_tasks = set()

    def schedule_domain(domain: str) -> None:
        if domain in seen or len(seen) >= MAX_DISCOVERED_DOMAINS:
            return
        seen.add(domain)
        scan_tasks.add(asyncio.create_task(scan_with_sem(domain)))

    for domain in normalized:
        schedule_domain(domain)

    yield f"data: {json.dumps({'type': 'start', 'total': len(seen), 'input_total': input_total, 'discovered': 0, 'enumerating': True})}\n\n"

    completed = 0
    queue_task = asyncio.create_task(discovery_queue.get())

    try:
        while active_producers or scan_tasks:
            wait_for = set(scan_tasks)
            if active_producers:
                wait_for.add(queue_task)
            done, _ = await asyncio.wait(
                wait_for,
                timeout=5,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                yield f"data: {json.dumps({'type': 'enumerating_progress'})}\n\n"
                continue

            if queue_task in done:
                events = [queue_task.result()]
                while not discovery_queue.empty():
                    events.append(discovery_queue.get_nowait())

                for event_type, value in events:
                    if event_type == "done":
                        active_producers -= 1
                    else:
                        schedule_domain(value)

                if active_producers:
                    queue_task = asyncio.create_task(discovery_queue.get())

            finished_scans = [task for task in done if task in scan_tasks]
            for task in finished_scans:
                scan_tasks.remove(task)
                result = task.result()
                completed += 1
                payload = {
                    "type": "result",
                    "completed": completed,
                    "total": len(seen),
                    "input_total": input_total,
                    "enumerating": active_producers > 0,
                    "result": result,
                }
                yield f"data: {json.dumps(payload)}\n\n"

        await asyncio.gather(*producers, return_exceptions=True)
        total = len(seen)
        discovered = max(0, total - input_total)
        yield f"data: {json.dumps({'type': 'done', 'total': total, 'completed': completed, 'discovered': discovered, 'enumeration_enabled': True})}\n\n"
    finally:
        if not queue_task.done():
            queue_task.cancel()
        for task in producers:
            if not task.done():
                task.cancel()
        for task in scan_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(queue_task, *producers, *scan_tasks, return_exceptions=True)


@app.post("/scan")
async def scan_endpoint(
    file: Optional[UploadFile] = File(None),
    domain: Optional[str] = Form(None),
    use_ai: bool = True,
    use_enum: bool = False,
):
    if file is not None:
        try:
            content = await file.read()
            domains = parse_domains_from_excel(content)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid Excel file") from exc
        if not domains:
            raise HTTPException(status_code=400, detail="No valid domains found in Excel file")
    elif domain:
        normalized = normalize_domain(domain)
        if not normalized:
            raise HTTPException(status_code=400, detail="Enter a valid domain, for example example.com")
        domains = [normalized]
        # A typed root domain is an enumeration request, even if a client omits
        # the UI's use_enum query parameter.
        use_enum = True
    else:
        raise HTTPException(status_code=400, detail="Upload an Excel file or enter a domain")

    return StreamingResponse(
        stream_scan(domains, use_ai, use_enum),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "codex": openai_available(),
        "model": OPENAI_MODEL,
        "tools": {
            "amass": bool(shutil.which("amass")),
            "subfinder": bool(shutil.which("subfinder")),
        },
    }
