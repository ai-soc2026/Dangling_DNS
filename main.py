import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import time
from typing import AsyncGenerator

import dns.resolver
import httpx
import openpyxl
from openai import OpenAI
from fastapi import FastAPI, File, UploadFile
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
ENUM_TIMEOUT_SECONDS = int(os.getenv("ENUM_TIMEOUT_SECONDS", "120"))


def openai_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    if re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain) and "." in domain:
        return domain
    return None


async def run_command_lines(cmd: list[str], timeout: int = ENUM_TIMEOUT_SECONDS) -> list[str]:
    if not shutil.which(cmd[0]):
        return []

    def _run() -> list[str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            return []
        return proc.stdout.splitlines()

    return await asyncio.to_thread(_run)


async def enumerate_subdomains(domain: str) -> list[str]:
    commands = [
        ["subfinder", "-silent", "-d", domain],
        ["amass", "enum", "-passive", "-d", domain],
    ]
    results = await asyncio.gather(*(run_command_lines(cmd) for cmd in commands))
    discovered = set()
    for lines in results:
        for line in lines:
            normalized = normalize_domain(line)
            if normalized and (normalized == domain or normalized.endswith(f".{domain}")):
                discovered.add(normalized)
    return sorted(discovered)


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
    dns_info = resolve_dns(domain)

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
    domains = await expand_domains(domains, use_enum)
    total = len(domains)
    yield f"data: {json.dumps({'type': 'start', 'total': total, 'input_total': input_total})}\n\n"

    semaphore = asyncio.Semaphore(10)  # max 10 concurrent scans

    async def scan_with_sem(domain, idx):
        async with semaphore:
            result = await scan_domain(domain, use_ai)
            return idx, result

    tasks = [scan_with_sem(d, i) for i, d in enumerate(domains)]
    completed = 0

    for coro in asyncio.as_completed(tasks):
        idx, result = await coro
        completed += 1
        payload = {
            "type": "result",
            "completed": completed,
            "total": total,
            "result": result,
        }
        yield f"data: {json.dumps(payload)}\n\n"

    yield f"data: {json.dumps({'type': 'done', 'total': total, 'completed': completed})}\n\n"


@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...), use_ai: bool = True, use_enum: bool = False):
    content = await file.read()
    domains = parse_domains_from_excel(content)

    if not domains:
        return {"error": "No valid domains found in Excel file"}

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
