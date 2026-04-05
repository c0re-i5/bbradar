"""
JavaScript analysis pipeline.

Discovers JS files from recon data, fetches them, and extracts:
  - API endpoints and hidden routes
  - Hardcoded secrets (AWS keys, API tokens, etc.)
  - Internal IPs and subdomains
  - Source map references
  - Cloud storage URLs (S3, GCS, Azure blobs)

Results are stored as recon_data entries for integration with
the probe system and reporting pipeline.
"""

import logging
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from ..core.database import get_connection
from ..core.audit import log_action
from .recon import add_recon, bulk_add_recon, list_recon

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Secret patterns  — compiled once
# ═══════════════════════════════════════════════════════════════════

_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(
        r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"
        r"|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"
    ),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    "discord_webhook": re.compile(r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    "firebase_url": re.compile(r"https://[a-zA-Z0-9-]+\.firebaseio\.com"),
    "s3_bucket": re.compile(
        r"[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com"
        r"|s3://[a-zA-Z0-9.\-]+"
        r"|s3-[a-zA-Z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9.\-]+"
    ),
    "gcs_bucket": re.compile(r"storage\.googleapis\.com/[a-zA-Z0-9._-]+"),
    "azure_blob": re.compile(r"[a-zA-Z0-9-]+\.blob\.core\.windows\.net"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "generic_api_key": re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]""", re.IGNORECASE),
}

_ENDPOINT_RE = re.compile(
    r"""['"`]"""
    r"(/"
    r"(?:api|v[0-9]|admin|internal|private|debug|graphql|rest|auth|oauth|user|account|config|settings)"
    r"[a-zA-Z0-9_/\-?=&.]*)"
    r"""['"`]"""
)

_ROUTE_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_/-]{2,})['"`]"""
)

_INTERNAL_IP_RE = re.compile(
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})"
)

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def _fetch_url(url: str, timeout: int = 15) -> str | None:
    """Fetch URL content safely. Returns text or None."""
    try:
        req = Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (BBRadar JS Analyzer)")
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = resp.read(5 * 1024 * 1024)  # 5MB limit
            return data.decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError, ValueError):
        return None


def analyze_js_content(content: str, source_url: str = "") -> dict:
    """
    Analyze a single JS file's content for secrets and endpoints.

    Returns {secrets: [...], endpoints: [...], internal_ips: [...],
             cloud_urls: [...], sourcemaps: [...], emails: [...]}.
    """
    findings = {
        "secrets": [],
        "endpoints": [],
        "internal_ips": [],
        "cloud_urls": [],
        "sourcemaps": [],
        "emails": [],
    }

    # Extract secrets
    for name, pattern in _SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            val = match.group(0)
            # Skip obvious false positives
            if len(val) < 8 or val.count("0") > len(val) * 0.6:
                continue
            findings["secrets"].append({
                "type": name,
                "value": val[:200],
                "source": source_url,
            })

    # Extract API endpoints
    seen_endpoints = set()
    for match in _ENDPOINT_RE.finditer(content):
        ep = match.group(1)
        if ep not in seen_endpoints and len(ep) > 2:
            seen_endpoints.add(ep)
            findings["endpoints"].append(ep)

    # Extract other routes (less specific, kept separate)
    for match in _ROUTE_RE.finditer(content):
        route = match.group(1)
        if (route not in seen_endpoints
                and len(route) > 3
                and not route.endswith((".js", ".css", ".png", ".jpg", ".svg", ".gif", ".ico",
                                        ".woff", ".woff2", ".ttf", ".eot"))
                and not route.startswith("//")
                and route.count("/") >= 2):
            seen_endpoints.add(route)
            findings["endpoints"].append(route)

    # Internal IPs
    for match in _INTERNAL_IP_RE.finditer(content):
        ip = match.group(0)
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            findings["internal_ips"].append(ip)

    # Cloud URLs
    for name in ("s3_bucket", "gcs_bucket", "azure_blob", "firebase_url"):
        for match in _SECRET_PATTERNS[name].finditer(content):
            findings["cloud_urls"].append({"type": name, "value": match.group(0)})

    # Source maps
    for match in _SOURCEMAP_RE.finditer(content):
        map_url = match.group(1)
        if source_url and not map_url.startswith("http"):
            map_url = urljoin(source_url, map_url)
        findings["sourcemaps"].append(map_url)

    # Emails
    for match in _EMAIL_RE.finditer(content):
        email = match.group(0)
        # Filter out common false positives
        if not email.endswith((".png", ".jpg", ".svg", ".gif", ".css", ".js")):
            findings["emails"].append(email)

    # Deduplicate
    findings["internal_ips"] = sorted(set(findings["internal_ips"]))
    findings["emails"] = sorted(set(findings["emails"]))
    findings["endpoints"] = sorted(set(findings["endpoints"]))

    return findings


def discover_js_files(target_id: int, db_path=None) -> list[str]:
    """
    Find JS file URLs from existing recon data for a target.

    Looks at js_file, url, and endpoint data types.
    """
    js_urls = set()

    # Direct js_file entries
    for entry in list_recon(target_id=target_id, data_type="js_file", db_path=db_path):
        js_urls.add(entry["value"])

    # URLs ending in .js
    for entry in list_recon(target_id=target_id, data_type="url", db_path=db_path):
        url = entry["value"]
        path = urlparse(url).path.lower()
        if path.endswith(".js") or ".js?" in path:
            js_urls.add(url)

    return sorted(js_urls)


def analyze_target(target_id: int, fetch: bool = True, max_files: int = 50,
                   db_path=None) -> dict:
    """
    Run JS analysis pipeline for a target.

    1. Discover JS files from recon data
    2. Optionally fetch and analyze each file
    3. Store findings as recon_data entries

    Returns summary dict.
    """
    js_urls = discover_js_files(target_id, db_path=db_path)

    if not js_urls:
        return {"js_files": 0, "analyzed": 0, "secrets": 0, "endpoints": 0, "errors": 0}

    all_secrets = []
    all_endpoints = []
    all_cloud = []
    all_ips = []
    analyzed = 0
    errors = 0

    for url in js_urls[:max_files]:
        if not fetch:
            analyzed += 1
            continue

        content = _fetch_url(url)
        if not content:
            errors += 1
            continue

        findings = analyze_js_content(content, url)
        analyzed += 1

        all_secrets.extend(findings["secrets"])
        all_endpoints.extend(findings["endpoints"])
        all_cloud.extend(findings["cloud_urls"])
        all_ips.extend(findings["internal_ips"])

        # Store source maps as js_file entries
        for sm in findings["sourcemaps"]:
            add_recon(target_id, "js_file", sm, source_tool="jsanalyzer", db_path=db_path)

    # Store results as recon_data
    stored_secrets = 0
    for s in all_secrets:
        rid = add_recon(target_id, "secret", f"[{s['type']}] {s['value']}",
                        source_tool="jsanalyzer",
                        raw_output=f"Found in: {s['source']}", db_path=db_path)
        if rid:
            stored_secrets += 1

    stored_endpoints = bulk_add_recon(
        target_id, "endpoint",
        sorted(set(all_endpoints)),
        source_tool="jsanalyzer", db_path=db_path,
    )

    for cloud in all_cloud:
        add_recon(target_id, "endpoint", f"[{cloud['type']}] {cloud['value']}",
                  source_tool="jsanalyzer", db_path=db_path)

    for ip in set(all_ips):
        add_recon(target_id, "other", f"[internal_ip] {ip}",
                  source_tool="jsanalyzer", db_path=db_path)

    log_action("js_analysis", "recon", None, {
        "target_id": target_id,
        "js_files": len(js_urls),
        "analyzed": analyzed,
        "secrets": stored_secrets,
        "endpoints": stored_endpoints,
    }, db_path)

    return {
        "js_files": len(js_urls),
        "analyzed": analyzed,
        "secrets": stored_secrets,
        "endpoints": stored_endpoints,
        "cloud_urls": len(all_cloud),
        "internal_ips": len(set(all_ips)),
        "errors": errors,
    }
