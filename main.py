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
from urllib.parse import urlparse

import dns.resolver
import httpx
import openpyxl
import database as db
from openai import OpenAI
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Subdomain Takeover Scanner")
db.initialize_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Provider-scoped takeover fingerprints. A response string is only considered
# evidence when the hostname also points to the matching provider. This avoids
# treating generic error pages such as "404 Not Found" as takeover findings.
TAKEOVER_SIGNATURES = (
    {
        "provider": "AWS S3",
        "cname_patterns": (r"\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$",),
        "header_patterns": {"server": (r"amazons3",)},
        "fingerprints": ("the specified bucket does not exist", "<code>nosuchbucket</code>"),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 95,
    },
    {
        "provider": "Agile CRM",
        "cname_patterns": (r"\.agilecrm\.com$",),
        "fingerprints": ("sorry, this page is no longer available.",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Bitbucket",
        "cname_patterns": (r"\.bitbucket\.io$",),
        "fingerprints": ("repository not found",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Gemfury",
        "cname_patterns": (r"\.furyns\.com$",),
        "fingerprints": ("404: this page could not be found.",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Ghost",
        "cname_patterns": (r"\.ghost\.io$",),
        "fingerprints": ("site unavailable.", "failed to resolve dns path for this host"),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Help Scout",
        "cname_patterns": (r"\.helpscoutdocs\.com$",),
        "fingerprints": ("no settings were found for this company:",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Ngrok",
        "cname_patterns": (r"\.ngrok\.io$",),
        "fingerprints": ("tunnel ", "ngrok.io not found"),
        "match_all": True,
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Pantheon",
        "cname_patterns": (r"\.pantheonsite\.io$",),
        "fingerprints": ("404 error unknown site!",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "ReadMe",
        "cname_patterns": (r"\.readme\.io$",),
        "fingerprints": ("the creators of this project are still working on making everything perfect!",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Strikingly",
        "cname_patterns": (r"\.strikinglydns\.com$",),
        "fingerprints": ("page not found.",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "Surge",
        "cname_patterns": (r"\.surge\.sh$",),
        "fingerprints": ("project not found",),
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "WordPress.com",
        "cname_patterns": (r"\.wordpress\.com$",),
        "fingerprints": ("do you want to register", "wordpress.com?"),
        "match_all": True,
        "severity": "high",
        "verdict": "takeover_vulnerable",
        "confidence": 90,
    },
    {
        "provider": "GitHub Pages",
        "cname_patterns": (r"\.github\.io$",),
        "header_patterns": {"server": (r"github\.com",)},
        "fingerprints": ("there isn't a github pages site here.",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Heroku",
        "cname_patterns": (r"\.herokuapp\.com$",),
        "header_patterns": {
            "server": (r"heroku", r"cowboy"),
            "via": (r"vegur",),
        },
        "fingerprints": ("no such app",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Netlify",
        "cname_patterns": (r"\.(?:netlify\.app|netlify\.com)$",),
        "header_patterns": {
            "server": (r"netlify",),
            "x-nf-request-id": (r".+",),
        },
        "fingerprints": ("not found - request id:",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Shopify",
        "cname_patterns": (r"\.myshopify\.com$",),
        "header_patterns": {
            "powered-by": (r"shopify",),
            "x-shopid": (r".+",),
            "x-shopify-stage": (r".+",),
        },
        "fingerprints": ("sorry, this shop is currently unavailable.", "store unavailable"),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Tumblr",
        "cname_patterns": (r"\.tumblr\.com$",),
        "fingerprints": ("whatever you were looking for doesn't currently exist at this address",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Vercel",
        "cname_patterns": (r"\.(?:vercel\.app|vercel-dns\.com)$",),
        "header_patterns": {
            "server": (r"vercel",),
            "x-vercel-error": (r"deployment_not_found",),
        },
        "fingerprints": ("deployment_not_found",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
    {
        "provider": "Webflow",
        "cname_patterns": (r"\.webflow\.io$",),
        "fingerprints": ("the page you are looking for doesn't exist or has been moved.",),
        "severity": "high",
        "verdict": "dangling_dns",
        "confidence": 85,
    },
)

# Branded vendor landing/error pages that identify a provider but do not, by
# themselves, indicate an unclaimed or takeover-capable resource.
VENDOR_DEFAULT_PAGE_SIGNATURES = (
    {
        "provider": "Permutive",
        "cname_patterns": (r"\.customer\.permutive\.app$",),
        "fingerprints": (
            "it is not here.",
            "whatever you are looking for, this is not it!",
            "don't need to try again.",
            "permutive.",
        ),
        "confidence": 80,
    },
)

# Only retain non-sensitive headers that can help identify a hosting provider.
# In particular, never persist Set-Cookie or authorization-related headers.
PROVIDER_EVIDENCE_HEADERS = {
    "powered-by",
    "server",
    "via",
    "x-amz-error-code",
    "x-azure-ref",
    "x-nf-request-id",
    "x-shopid",
    "x-shopify-stage",
    "x-vercel-error",
}

REVIEW_HTTP_STATUSES = {402, 404, 410, 421, 451}

# Known organization-controlled authentication destinations. Keep this list
# hostname-specific: trusting all of okta.com/oktapreview.com would allow an
# unrelated tenant to hide a malicious redirect.
DEFAULT_REDIRECT_DOMAIN_ALLOWLIST = {
    "condenast-hub.okta-emea.com",
    "condenast-hub.oktapreview.com",
}

CLOUD_CNAME_PATTERNS = [
    (r"\.s3\.amazonaws\.com$", "AWS S3"),
    (r"\.s3-website.*\.amazonaws\.com$", "AWS S3 Website"),
    (r"\.azurewebsites\.net$", "Azure Web Apps"),
    (r"\.azureedge\.net$", "Azure CDN"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.customer\.permutive\.app$", "Permutive"),
    (r"\.herokuapp\.com$", "Heroku"),
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.netlify\.app$", "Netlify"),
    (r"\.netlify\.com$", "Netlify"),
    (r"\.vercel\.app$", "Vercel"),
    (r"\.vercel-dns\.com$", "Vercel"),
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
    (r"\.agilecrm\.com$", "Agile CRM"),
    (r"\.bitbucket\.io$", "Bitbucket"),
    (r"\.furyns\.com$", "Gemfury"),
    (r"\.ngrok\.io$", "Ngrok"),
    (r"\.readme\.io$", "ReadMe"),
    (r"\.strikinglydns\.com$", "Strikingly"),
    (r"\.tumblr\.com$", "Tumblr"),
    (r"\.wordpress\.com$", "WordPress.com"),
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
              "a_records": [], "aaaa_records": [], "resolves": False,
              "nxdomain": False, "cname_target_nxdomain": False,
              "record_types": [], "resolution_status": "Unknown",
              "query_errors": {}}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    def remember_error(record_type: str, exc: Exception) -> None:
        if isinstance(exc, dns.resolver.Timeout):
            label = "Timeout"
        elif isinstance(exc, dns.resolver.NoNameservers):
            label = "SERVFAIL / no nameservers available"
        else:
            label = type(exc).__name__
        result["query_errors"][record_type] = label

    def add_record_type(record_type: str) -> None:
        if record_type not in result["record_types"]:
            result["record_types"].append(record_type)

    def resolve_cname_target(initial_target: str) -> None:
        """Follow a discovered CNAME and explicitly validate its destination."""
        current_target = initial_target.rstrip(".")
        visited = set()

        # Protect the scan from malformed or cyclic CNAME chains.
        for _ in range(10):
            normalized_target = current_target.lower()
            if normalized_target in visited:
                result["query_errors"]["CNAME target"] = "CNAME loop detected"
                return
            visited.add(normalized_target)

            next_target = None
            try:
                answers = resolver.resolve(current_target, "CNAME")
                next_target = str(answers[0].target).rstrip(".")
            except dns.resolver.NXDOMAIN:
                result["cname_target_nxdomain"] = True
                return
            except dns.resolver.NoAnswer:
                pass
            except Exception as exc:
                remember_error("CNAME target CNAME", exc)

            try:
                answers = resolver.resolve(current_target, "A")
                result["has_a"] = True
                result["a_records"] = [str(record) for record in answers]
                result["resolves"] = True
                add_record_type("A")
                return
            except dns.resolver.NXDOMAIN:
                result["cname_target_nxdomain"] = True
                return
            except dns.resolver.NoAnswer:
                pass
            except Exception as exc:
                remember_error("CNAME target A", exc)

            try:
                answers = resolver.resolve(current_target, "AAAA")
                result["aaaa_records"] = [str(record) for record in answers]
                result["resolves"] = True
                add_record_type("AAAA")
                return
            except dns.resolver.NXDOMAIN:
                result["cname_target_nxdomain"] = True
                return
            except dns.resolver.NoAnswer:
                pass
            except Exception as exc:
                remember_error("CNAME target AAAA", exc)

            if not next_target:
                return
            current_target = next_target

        result["query_errors"]["CNAME target"] = "CNAME chain exceeded 10 links"

    try:
        answers = resolver.resolve(domain, "CNAME")
        result["has_cname"] = True
        result["cname_target"] = str(answers[0].target).rstrip(".")
        add_record_type("CNAME")
    except dns.resolver.NXDOMAIN:
        result["nxdomain"] = True
        result["resolution_status"] = "NXDOMAIN"
        return result
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:
        remember_error("CNAME", exc)

    try:
        answers = resolver.resolve(domain, "A")
        result["has_a"] = True
        result["a_records"] = [str(r) for r in answers]
        result["resolves"] = True
        add_record_type("A")
    except dns.resolver.NXDOMAIN:
        if result["has_cname"]:
            result["cname_target_nxdomain"] = True
        else:
            result["nxdomain"] = True
    except dns.resolver.NoAnswer:
        pass
    except Exception as exc:
        remember_error("A", exc)

    if not result["resolves"] and not result["nxdomain"] and not result["cname_target_nxdomain"]:
        try:
            answers = resolver.resolve(domain, "AAAA")
            result["aaaa_records"] = [str(r) for r in answers]
            result["resolves"] = True
            add_record_type("AAAA")
        except dns.resolver.NXDOMAIN:
            if result["has_cname"]:
                result["cname_target_nxdomain"] = True
            else:
                result["nxdomain"] = True
        except dns.resolver.NoAnswer:
            pass
        except Exception as exc:
            remember_error("AAAA", exc)

    # Some resolvers return the original CNAME as a successful NOERROR answer
    # but do not raise NXDOMAIN while resolving the original name's A/AAAA
    # records. Validate the actual destination explicitly so a broken target
    # cannot fall through to the default Clean verdict.
    if (
        result["has_cname"]
        and result["cname_target"]
        and not result["resolves"]
        and not result["nxdomain"]
        and not result["cname_target_nxdomain"]
    ):
        resolve_cname_target(result["cname_target"])

    if result["nxdomain"]:
        result["resolution_status"] = "NXDOMAIN"
    elif result["cname_target_nxdomain"]:
        result["resolution_status"] = "CNAME target NXDOMAIN"
    elif result["resolves"]:
        result["resolution_status"] = "Resolved"
    elif result["query_errors"]:
        errors = set(result["query_errors"].values())
        result["resolution_status"] = (
            "DNS query failed: " + ", ".join(sorted(errors))
        )
    elif result["has_cname"]:
        result["resolution_status"] = "CNAME found; no A/AAAA answer"
    else:
        result["resolution_status"] = "No A/AAAA/CNAME answer"

    return result


async def fetch_http(domain: str) -> dict:
    result = {"attempted": False, "status": None, "title": None,
              "body_snippet": "", "headers": {}, "url": None, "error": None}
    errors = []
    for scheme in ["https", "http"]:
        requested_url = f"{scheme}://{domain}"
        result["attempted"] = True
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                         verify=False) as client:
                resp = await client.get(requested_url,
                                        headers={"User-Agent": "Mozilla/5.0"})
                result["status"] = resp.status_code
                result["url"] = str(resp.url)
                result["headers"] = {
                    name: resp.headers[name][:300]
                    for name in PROVIDER_EVIDENCE_HEADERS
                    if name in resp.headers
                }
                body = resp.text[:3000]
                result["body_snippet"] = body
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]
                return result
        except Exception as e:
            message = str(e).strip() or type(e).__name__
            errors.append(f"{scheme.upper()}: {message[:140]}")
    result["error"] = " | ".join(errors) or "No HTTP response"
    return result


def rule_based_analysis(domain: str, dns_info: dict, http_info: dict) -> dict:
    verdict = "clean"
    severity = "info"
    provider = None
    provider_evidence = None
    reason = "No issues detected"
    confidence = 0

    # NXDOMAIN for the queried hostname means there is no active DNS pointer.
    if dns_info["nxdomain"]:
        verdict = "inactive"
        reason = "Hostname returns NXDOMAIN — no active DNS record was found"
    elif (
        dns_info.get("resolves") is False
        and not dns_info.get("cname_target")
        and not dns_info.get("record_types")
        and not dns_info.get("query_errors")
    ):
        verdict = "inactive"
        reason = "Hostname has no A, AAAA, or CNAME answer — no active web DNS target was found"
    elif dns_info.get("resolves") is False and dns_info.get("query_errors"):
        verdict = "scan_error"
        severity = "info"
        reason = "DNS queries failed; the hostname could not be classified reliably"

    # Check CNAME points to known cloud provider
    cname = dns_info.get("cname_target", "") or ""
    cname_target_nxdomain = dns_info.get("cname_target_nxdomain", False)
    for pattern, prov in CLOUD_CNAME_PATTERNS:
        if re.search(pattern, cname, re.IGNORECASE):
            provider = prov
            provider_evidence = f"Identified from CNAME: {cname}"
            if cname_target_nxdomain:
                verdict = "dangling_dns"
                severity = "high"
                reason = f"CNAME points to {prov} ({cname}), but the target returns NXDOMAIN"
                confidence = 90
            break

    if cname and cname_target_nxdomain and verdict == "clean":
        verdict = "dangling_dns"
        severity = "high"
        reason = f"CNAME exists, but its target ({cname}) returns NXDOMAIN"
        confidence = 85

    # Check provider-scoped HTTP failure signatures. CNAME identity remains
    # supported, while A/AAAA-backed sites can be identified using a limited
    # set of safe provider response headers.
    body = (http_info.get("body_snippet") or "").lower()
    title = (http_info.get("title") or "").lower()
    response_text = f"{title}\n{body}"
    response_headers = {
        str(name).lower(): str(value).lower()
        for name, value in (http_info.get("headers") or {}).items()
    }
    for signature in TAKEOVER_SIGNATURES:
        cname_matches = any(
            re.search(pattern, cname, re.IGNORECASE)
            for pattern in signature["cname_patterns"]
        )
        header_matches = []
        for header_name, patterns in signature.get("header_patterns", {}).items():
            header_value = response_headers.get(header_name, "")
            if header_value and any(
                re.search(pattern, header_value, re.IGNORECASE)
                for pattern in patterns
            ):
                header_matches.append(f"{header_name}={header_value[:80]}")

        provider_identity_matches = cname_matches or bool(header_matches)
        fingerprints = signature["fingerprints"]
        if signature.get("match_all"):
            body_matches = all(fingerprint in response_text for fingerprint in fingerprints)
        else:
            body_matches = any(fingerprint in response_text for fingerprint in fingerprints)

        if provider_identity_matches and body_matches:
            verdict = (
                signature["verdict"]
                if cname_matches
                else "provider_resource_risk"
            )
            severity = signature["severity"]
            provider = signature["provider"]
            provider_evidence = (
                f"Identified from CNAME: {cname}"
                if cname_matches
                else "Identified from HTTP header: " + ", ".join(header_matches)
            )
            reason = (
                f"Provider-specific unavailable-resource fingerprint detected for {provider}; "
                "manual ownership validation is required"
            )
            confidence = signature["confidence"]
            break

        # Keep provider identity as evidence even when its exact failure page
        # is absent. This alone is not enough to create a High finding.
        if provider is None and header_matches:
            provider = signature["provider"]
            provider_evidence = "Identified from HTTP header: " + ", ".join(header_matches)

    if verdict == "clean":
        for signature in VENDOR_DEFAULT_PAGE_SIGNATURES:
            cname_matches = any(
                re.search(pattern, cname, re.IGNORECASE)
                for pattern in signature["cname_patterns"]
            )
            page_matches = all(
                fingerprint in response_text
                for fingerprint in signature["fingerprints"]
            )
            if cname_matches and page_matches:
                provider = signature["provider"]
                provider_evidence = f"Identified from CNAME and branded page: {cname}"
                verdict = "vendor_default_page"
                severity = "info"
                reason = (
                    f"{provider}-branded default page returned HTTP "
                    f"{http_info.get('status')}; no dangling or takeover fingerprint was detected"
                )
                confidence = signature["confidence"]
                break

    status = http_info.get("status")
    review_http_failure = status in REVIEW_HTTP_STATUSES or (
        isinstance(status, int) and status >= 500
    )
    if verdict == "clean" and review_http_failure:
        verdict = "provider_service_error" if provider else "http_observation"
        severity = "medium" if provider else "info"
        reason = (
            f"{provider} returned HTTP {status}; manual service validation is required"
            if provider
            else f"Generic HTTP {status} response observed without provider risk evidence"
        )
        confidence = 60 if provider else 20
    elif (
        verdict == "clean"
        and dns_info.get("resolves")
        and http_info.get("attempted")
        and status is None
    ):
        verdict = "scan_error"
        severity = "info"
        reason = "HTTP checks failed; the hostname could not be classified reliably"

    # A resolving hostname can still be compromised or abandoned. Flag an
    # unexpected redirect to an unrelated hostname instead of treating the
    # final HTTP 200 response as clean. Legitimate external destinations can
    # be supplied as a comma-separated list in REDIRECT_DOMAIN_ALLOWLIST.
    final_url = http_info.get("url") or ""
    final_hostname = (urlparse(final_url).hostname or "").lower().rstrip(".")
    requested_hostname = domain.lower().rstrip(".")
    allowed_redirect_hosts = DEFAULT_REDIRECT_DOMAIN_ALLOWLIST | {
        host.strip().lower().rstrip(".")
        for host in os.getenv("REDIRECT_DOMAIN_ALLOWLIST", "").split(",")
        if host.strip()
    }

    def same_domain_family(left: str, right: str) -> bool:
        if not left or not right:
            return True
        if left == right or left.endswith(f".{right}") or right.endswith(f".{left}"):
            return True
        # Treat sibling hostnames below the same conventional registrable
        # domain as related (for example, app.example.com -> www.example.com).
        left_parts = left.split(".")
        right_parts = right.split(".")
        return len(left_parts) >= 2 and len(right_parts) >= 2 and left_parts[-2:] == right_parts[-2:]

    redirect_is_allowed = any(
        final_hostname == allowed or final_hostname.endswith(f".{allowed}")
        for allowed in allowed_redirect_hosts
    )
    if (
        final_hostname
        and not same_domain_family(requested_hostname, final_hostname)
        and not redirect_is_allowed
    ):
        verdict = "suspicious_redirect"
        severity = "critical"
        reason = (
            f"Request for {requested_hostname} redirects to unapproved external host "
            f"{final_hostname}; immediate investigation and containment are required"
        )
        confidence = 90

    return {
        "verdict": verdict,
        "severity": severity,
        "provider": provider,
        "provider_evidence": provider_evidence,
        "reason": reason,
        "confidence": confidence,
    }


def apply_historical_change_detection(
    result: dict,
    previous: Optional[dict],
) -> dict:
    """Flag an unresolved dangling CNAME that unexpectedly becomes reachable."""
    if not previous or result.get("verdict") != "clean":
        return result

    previous_evidence = previous.get("evidence") or {}
    previous_dns = previous_evidence.get("dns") or {}
    current_dns = result.get("dns") or {}
    current_http = result.get("http") or {}
    previous_verdict = previous.get("verdict") or previous_evidence.get("verdict")
    remediation_status = previous.get("remediation_status") or "Open"

    previous_was_dangling = (
        previous_verdict == "dangling_dns"
        and bool(previous_dns.get("cname_target_nxdomain"))
    )
    previous_validation_open = previous_verdict == "ownership_validation_required"
    if not (previous_was_dangling or previous_validation_open):
        return result
    if remediation_status in {"Resolved", "False Positive"}:
        return result

    previous_cname = str(previous_dns.get("cname") or previous.get("cname") or "").lower().rstrip(".")
    current_cname = str(current_dns.get("cname") or "").lower().rstrip(".")
    if not previous_cname or previous_cname != current_cname:
        return result

    http_status = current_http.get("status")
    http_success = isinstance(http_status, int) and 200 <= http_status < 400
    if not current_dns.get("resolves") or not http_success:
        return result

    original_dangling = previous_evidence.get("history_evidence") or {
        "previous_result_id": previous.get("id"),
        "previous_scan_id": previous.get("scan_id"),
        "previous_created_at": previous.get("created_at"),
        "previous_verdict": previous_verdict,
        "previous_severity": previous.get("severity") or previous_evidence.get("severity"),
        "previous_dns_state": previous_dns.get("resolution_status"),
        "previous_cname": previous_cname,
        "previous_cname_target_nxdomain": bool(previous_dns.get("cname_target_nxdomain")),
        "previous_remediation_status": remediation_status,
    }
    result["history_evidence"] = {
        **original_dangling,
        "compared_result_id": previous.get("id"),
        "compared_created_at": previous.get("created_at"),
        "current_dns_state": current_dns.get("resolution_status"),
        "current_cname": current_cname,
        "current_http_status": http_status,
        "current_http_url": current_http.get("url"),
        "change": "Previously dangling CNAME target now resolves without recorded remediation",
    }
    result["verdict"] = "ownership_validation_required"
    result["severity"] = "high"
    result["confidence"] = 80
    result["reason"] = (
        f"Previously dangling CNAME target ({current_cname}) now resolves and returns "
        f"HTTP {http_status} without recorded remediation; verify resource ownership"
    )
    return result


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
    http_info = {"attempted": False, "status": None, "title": None,
                 "body_snippet": "", "headers": {}, "url": None,
                 "error": "Not attempted because DNS did not resolve"}
    if not dns_info["nxdomain"] and dns_info["resolves"]:
        http_info = await fetch_http(domain)

    # Rule-based analysis
    rule_result = rule_based_analysis(domain, dns_info, http_info)

    # AI analysis only for actionable findings
    ai_analysis = None
    if use_ai and rule_result["verdict"] not in {"clean", "inactive"}:
        ai_analysis = await ask_codex(domain, dns_info, http_info, rule_result)

    elapsed = round(time.time() - start, 2)

    return {
        "domain": domain,
        "verdict": rule_result["verdict"],
        "severity": rule_result["severity"],
        "provider": rule_result["provider"],
        "provider_evidence": rule_result.get("provider_evidence") or (
            "No provider identity matched the DNS or HTTP evidence"
            if not dns_info["cname_target"]
            else "CNAME does not match a provider in the takeover-signature database"
        ),
        "reason": rule_result["reason"],
        "confidence": rule_result["confidence"],
        "ai_analysis": ai_analysis,
        "dns": {
            "resolves": dns_info["resolves"],
            "nxdomain": dns_info["nxdomain"],
            "cname": dns_info["cname_target"],
            "cname_target_nxdomain": dns_info.get("cname_target_nxdomain", False),
            "a_records": dns_info["a_records"],
            "aaaa_records": dns_info.get("aaaa_records", []),
            "record_types": dns_info.get("record_types", []),
            "resolution_status": dns_info.get("resolution_status", "Unknown"),
            "query_errors": dns_info.get("query_errors", {}),
        },
        "http": {
            "attempted": http_info.get("attempted", False),
            "status": http_info["status"],
            "title": http_info["title"],
            "url": http_info.get("url"),
            "error": http_info.get("error"),
            "provider_headers": http_info.get("headers", {}),
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


async def persisted_stream_scan(
    scan_id: str,
    domains: list[str],
    use_ai: bool,
    use_enum: bool,
) -> AsyncGenerator[str, None]:
    """Persist each SSE event without changing enumeration or detection logic."""
    terminal_status_written = False
    completed_count = 0
    total_count = len(domains)
    discovered_count = 0

    try:
        async for chunk in stream_scan(domains, use_ai, use_enum):
            raw_payload = chunk[6:].strip() if chunk.startswith("data: ") else ""
            payload = json.loads(raw_payload) if raw_payload else {}
            payload["scan_id"] = scan_id
            event_type = payload.get("type")

            if event_type == "start":
                total_count = int(payload.get("total") or total_count)
                await asyncio.to_thread(
                    db.update_scan_totals,
                    scan_id,
                    total_count=total_count,
                    discovered_count=max(0, total_count - len(domains)),
                )
            elif event_type == "result":
                completed_count = int(payload.get("completed") or completed_count)
                total_count = int(payload.get("total") or total_count)
                previous_result = await asyncio.to_thread(
                    db.get_latest_result_for_domain,
                    payload["result"]["domain"],
                    exclude_scan_id=scan_id,
                )
                payload["result"] = apply_historical_change_detection(
                    payload["result"],
                    previous_result,
                )
                result_id = await asyncio.to_thread(
                    db.save_scan_result,
                    scan_id,
                    payload["result"],
                    completed_count=completed_count,
                    total_count=total_count,
                )
                payload["result"]["result_id"] = result_id
            elif event_type == "done":
                completed_count = int(payload.get("completed") or completed_count)
                total_count = int(payload.get("total") or total_count)
                discovered_count = int(payload.get("discovered") or 0)
                await asyncio.to_thread(
                    db.finish_scan,
                    scan_id,
                    status="completed",
                    completed_count=completed_count,
                    total_count=total_count,
                    discovered_count=discovered_count,
                )
                terminal_status_written = True

            yield f"data: {json.dumps(payload)}\n\n"
    except asyncio.CancelledError:
        await asyncio.to_thread(db.stop_scan_if_running, scan_id)
        terminal_status_written = True
        raise
    except Exception as exc:
        await asyncio.to_thread(
            db.finish_scan,
            scan_id,
            status="failed",
            completed_count=completed_count,
            total_count=total_count,
            discovered_count=discovered_count,
            error=str(exc)[:500],
        )
        terminal_status_written = True
        raise
    finally:
        if not terminal_status_written:
            await asyncio.to_thread(db.stop_scan_if_running, scan_id)


class RemediationUpdate(BaseModel):
    status: str
    assigned_owner: Optional[str] = Field(default=None, max_length=200)
    analyst_comment: Optional[str] = Field(default=None, max_length=4000)


@app.post("/scan")
async def scan_endpoint(
    file: Optional[UploadFile] = File(None),
    domain: Optional[str] = Form(None),
    use_ai: bool = True,
    use_enum: bool = False,
):
    if file is not None:
        input_type = "excel"
        input_value = file.filename or "Uploaded Excel file"
        try:
            content = await file.read()
            domains = parse_domains_from_excel(content)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid Excel file") from exc
        if not domains:
            raise HTTPException(status_code=400, detail="No valid domains found in Excel file")
    elif domain:
        input_type = "domain"
        normalized = normalize_domain(domain)
        if not normalized:
            raise HTTPException(status_code=400, detail="Enter a valid domain, for example example.com")
        domains = [normalized]
        input_value = normalized
        # A typed root domain is an enumeration request, even if a client omits
        # the UI's use_enum query parameter.
        use_enum = True
    else:
        raise HTTPException(status_code=400, detail="Upload an Excel file or enter a domain")

    scan_id = await asyncio.to_thread(
        db.create_scan,
        input_type=input_type,
        input_value=input_value,
        source_domains=domains,
        use_ai=use_ai,
        use_enum=use_enum,
    )

    return StreamingResponse(
        persisted_stream_scan(scan_id, domains, use_ai, use_enum),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/history/scans")
async def history_scans(
    q: str = "",
    status: str = "",
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    if status and status not in {"running", "completed", "stopped", "failed"}:
        raise HTTPException(status_code=400, detail="Invalid scan status")
    return await asyncio.to_thread(
        db.list_scans,
        query=q,
        status=status,
        limit=limit,
        offset=offset,
    )


@app.get("/history/scans/{scan_id}")
async def history_scan(scan_id: str):
    scan = await asyncio.to_thread(db.get_scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/history/scans/{scan_id}/results")
async def history_scan_results(
    scan_id: str,
    q: str = "",
    verdict: str = "",
    severity: str = "",
    remediation_status: str = "",
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    if not await asyncio.to_thread(db.get_scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await asyncio.to_thread(
        db.list_scan_results,
        scan_id,
        query=q,
        verdict=verdict,
        severity=severity,
        remediation_status=remediation_status,
        limit=limit,
        offset=offset,
    )


@app.get("/history/search")
async def history_search(
    q: str,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    if not q.strip():
        raise HTTPException(status_code=400, detail="Enter a search term")
    return await asyncio.to_thread(
        db.search_results,
        query=q,
        limit=limit,
        offset=offset,
    )


@app.get("/history/results/{result_id}")
async def history_result(result_id: int):
    result = await asyncio.to_thread(db.get_result, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return result


@app.patch("/history/results/{result_id}")
async def update_history_result(result_id: int, update: RemediationUpdate):
    allowed_statuses = {"Open", "Investigating", "False Positive", "Resolved"}
    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Status must be one of: {', '.join(sorted(allowed_statuses))}",
        )
    result = await asyncio.to_thread(
        db.update_remediation,
        result_id,
        status=update.status,
        assigned_owner=update.assigned_owner,
        analyst_comment=update.analyst_comment,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return result


@app.get("/database")
async def database_json_view(
    scan_limit: int = Query(default=100, ge=1, le=500),
    result_limit: int = Query(default=500, ge=1, le=2000),
):
    """Read-only JSON view of stored scans and results for demonstrations."""
    scans, results, database_status = await asyncio.gather(
        asyncio.to_thread(db.list_scans, limit=scan_limit, offset=0),
        asyncio.to_thread(db.search_results, query="", limit=result_limit, offset=0),
        asyncio.to_thread(db.database_health),
    )
    return {
        "database": {
            "type": (
                "PostgreSQL"
                if database_status["backend"] == "postgresql"
                else "SQLite"
            ),
            "name": database_status["database"],
            "read_only": True,
        },
        "scans": {
            "total": scans["total"],
            "displayed": len(scans["items"]),
            "rows": scans["items"],
        },
        "scan_results": {
            "total": results["total"],
            "displayed": len(results["items"]),
            "rows": results["items"],
        },
    }


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
        "database": await asyncio.to_thread(db.database_health),
    }
