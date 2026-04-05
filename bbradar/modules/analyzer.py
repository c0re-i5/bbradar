"""
Web page analyzer module.

Fetches a URL and performs passive analysis:
  - Technology fingerprinting (headers + HTML patterns)
  - Security header audit (HSTS, CSP, X-Frame-Options, etc.)
  - Form and input discovery (login forms, hidden fields, CSRF tokens)
  - Link and endpoint extraction
  - JS file discovery
  - HTML comment extraction
  - Cookie attribute analysis
  - Meta tag / header information leakage

Results are stored as recon_data entries and returned as a structured
report for display or export.
"""

import html as html_lib
import logging
import re
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPCookieProcessor, urlopen

from ..core.database import get_connection
from ..core.audit import log_action
from .recon import add_recon, bulk_add_recon

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Technology signatures  — (header_or_tag, pattern, tech_name)
# ═══════════════════════════════════════════════════════════════════
_TECH_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    # Server headers
    ("header:server", re.compile(r"nginx", re.I), "Nginx"),
    ("header:server", re.compile(r"apache", re.I), "Apache"),
    ("header:server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("header:server", re.compile(r"IIS", re.I), "Microsoft IIS"),
    ("header:server", re.compile(r"LiteSpeed", re.I), "LiteSpeed"),
    ("header:x-powered-by", re.compile(r"PHP", re.I), "PHP"),
    ("header:x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET"),
    ("header:x-powered-by", re.compile(r"Express", re.I), "Express.js"),
    ("header:x-powered-by", re.compile(r"Next\.js", re.I), "Next.js"),
    ("header:x-generator", re.compile(r"WordPress", re.I), "WordPress"),
    ("header:x-generator", re.compile(r"Drupal", re.I), "Drupal"),
    # HTML patterns
    ("html", re.compile(r"wp-content/", re.I), "WordPress"),
    ("html", re.compile(r"wp-includes/", re.I), "WordPress"),
    ("html", re.compile(r"/sites/default/files", re.I), "Drupal"),
    ("html", re.compile(r"Joomla!", re.I), "Joomla"),
    ("html", re.compile(r'content="WordPress', re.I), "WordPress"),
    ("html", re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    ("html", re.compile(r"react", re.I), "React"),
    ("html", re.compile(r"__next", re.I), "Next.js"),
    ("html", re.compile(r"__nuxt", re.I), "Nuxt.js"),
    ("html", re.compile(r"ng-app|ng-controller", re.I), "AngularJS"),
    ("html", re.compile(r"ember", re.I), "Ember.js"),
    ("html", re.compile(r"vue\.js|v-bind|v-model", re.I), "Vue.js"),
    ("html", re.compile(r"jquery", re.I), "jQuery"),
    ("html", re.compile(r"bootstrap", re.I), "Bootstrap"),
    ("html", re.compile(r"tailwindcss|tailwind", re.I), "Tailwind CSS"),
    ("html", re.compile(r"google-analytics|gtag", re.I), "Google Analytics"),
    ("html", re.compile(r"recaptcha", re.I), "reCAPTCHA"),
    ("html", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("html", re.compile(r"akamai", re.I), "Akamai"),
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.DOTALL | re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#][^'"]*?)['"]""", re.IGNORECASE)
_META_RE = re.compile(r"<meta\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL | re.IGNORECASE)

# Sensitive meta content patterns
_LEAKY_META_PATTERNS = [
    re.compile(r"author", re.I),
    re.compile(r"generator", re.I),
    re.compile(r"msapplication", re.I),
    re.compile(r"csrf", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"version", re.I),
]


def _attr(tag_html: str, name: str) -> str:
    """Extract an attribute value from an HTML tag string."""
    m = re.search(rf"""{name}\s*=\s*['"]([^'"]*?)['"]""", tag_html, re.IGNORECASE)
    return m.group(1) if m else ""


def _fetch_page(url: str, timeout: int = 20) -> tuple[dict, str] | None:
    """
    Fetch a URL and return (headers_dict, body_text).
    Returns None on error.
    """
    try:
        jar = CookieJar()
        opener = build_opener(HTTPCookieProcessor(jar))
        req = Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")
        resp = opener.open(req, timeout=timeout)

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(10 * 1024 * 1024)  # 10MB limit
        text = body.decode("utf-8", errors="replace")

        # Attach cookies to headers for analysis
        cookies = []
        for cookie in jar:
            parts = [f"{cookie.name}={cookie.value}"]
            if cookie.secure:
                parts.append("Secure")
            if getattr(cookie, "has_nonstandard_attr", lambda a: False)("HttpOnly"):
                parts.append("HttpOnly")
            if cookie.path:
                parts.append(f"Path={cookie.path}")
            cookies.append("; ".join(parts))
        if cookies:
            headers["_cookies"] = cookies

        return headers, text
    except (HTTPError, URLError, OSError, ValueError) as e:
        logger.warning("Failed to fetch %s: %s", url, e)
        return None


def analyze_page(url: str) -> dict:
    """
    Analyze a web page and return structured findings.

    Returns dict with keys: url, title, technologies, security_headers,
    forms, comments, js_files, links, meta_leaks, cookies, endpoints.
    """
    result = {
        "url": url,
        "title": "",
        "technologies": [],
        "security_headers": {"present": {}, "missing": []},
        "forms": [],
        "comments": [],
        "js_files": [],
        "links": [],
        "meta_leaks": [],
        "cookies": [],
        "endpoints": [],
        "errors": [],
    }

    fetched = _fetch_page(url)
    if fetched is None:
        result["errors"].append(f"Failed to fetch {url}")
        return result

    headers, body = fetched
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # ── Title ─────────────────────────────────────────────────────
    m = _TITLE_RE.search(body)
    if m:
        result["title"] = html_lib.unescape(m.group(1).strip())[:200]

    # ── Technology fingerprinting ─────────────────────────────────
    seen_tech = set()
    for source, pattern, tech_name in _TECH_SIGNATURES:
        if source.startswith("header:"):
            header_name = source.split(":", 1)[1]
            val = headers.get(header_name, "")
            if pattern.search(val) and tech_name not in seen_tech:
                seen_tech.add(tech_name)
                result["technologies"].append({
                    "name": tech_name,
                    "source": f"header:{header_name}",
                    "evidence": val[:100],
                })
        elif source == "html":
            if pattern.search(body) and tech_name not in seen_tech:
                seen_tech.add(tech_name)
                result["technologies"].append({
                    "name": tech_name,
                    "source": "html",
                })

    # ── Security headers audit ────────────────────────────────────
    for hdr in _SECURITY_HEADERS:
        val = headers.get(hdr)
        if val:
            result["security_headers"]["present"][hdr] = val
        else:
            result["security_headers"]["missing"].append(hdr)

    # ── Forms ─────────────────────────────────────────────────────
    for m in _FORM_RE.finditer(body):
        form_attrs = m.group(1)
        form_body = m.group(2)
        form = {
            "action": _attr(form_attrs, "action"),
            "method": _attr(form_attrs, "method").upper() or "GET",
            "inputs": [],
        }
        for inp in _INPUT_RE.finditer(form_body):
            inp_html = inp.group(1)
            form["inputs"].append({
                "name": _attr(inp_html, "name"),
                "type": _attr(inp_html, "type") or "text",
                "value": _attr(inp_html, "value")[:50],
            })
        result["forms"].append(form)

    # ── HTML comments ─────────────────────────────────────────────
    for m in _COMMENT_RE.finditer(body):
        comment = m.group(1).strip()
        # Skip empty, conditional comments, and common noise
        if (comment
                and not comment.startswith("[if ")
                and not comment.startswith("[endif")
                and len(comment) > 3
                and len(comment) < 2000):
            result["comments"].append(comment[:500])

    if len(result["comments"]) > 50:
        result["comments"] = result["comments"][:50]

    # ── JS files ──────────────────────────────────────────────────
    for m in _SCRIPT_SRC_RE.finditer(body):
        src = m.group(1)
        if not src.startswith(("http://", "https://", "//")):
            src = urljoin(url, src)
        elif src.startswith("//"):
            src = f"{parsed_url.scheme}:{src}"
        result["js_files"].append(src)

    result["js_files"] = sorted(set(result["js_files"]))

    # ── Links and endpoints ───────────────────────────────────────
    internal_links = set()
    external_links = set()
    endpoints = set()

    for m in _LINK_RE.finditer(body):
        href = m.group(1).strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue

        # Resolve relative URLs
        if not href.startswith(("http://", "https://", "//")):
            href = urljoin(url, href)
        elif href.startswith("//"):
            href = f"{parsed_url.scheme}:{href}"

        href_parsed = urlparse(href)

        if href_parsed.netloc == parsed_url.netloc or not href_parsed.netloc:
            internal_links.add(href)
            # Interesting endpoints
            path = href_parsed.path
            if (path and path != "/"
                    and not path.endswith((".css", ".png", ".jpg", ".jpeg", ".gif",
                                          ".svg", ".ico", ".woff", ".woff2", ".ttf"))):
                endpoints.add(path)
        else:
            external_links.add(href)

    result["links"] = {
        "internal": sorted(internal_links)[:200],
        "external": sorted(external_links)[:100],
    }
    result["endpoints"] = sorted(endpoints)[:200]

    # ── Meta tag leaks ────────────────────────────────────────────
    for m in _META_RE.finditer(body):
        tag = m.group(1)
        name = _attr(tag, "name") or _attr(tag, "property") or _attr(tag, "http-equiv")
        content = _attr(tag, "content")
        if name and content:
            for pat in _LEAKY_META_PATTERNS:
                if pat.search(name):
                    result["meta_leaks"].append({"name": name, "content": content[:200]})
                    break

    # ── Cookies ───────────────────────────────────────────────────
    raw_cookies = headers.get("_cookies", [])
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        for part in re.split(r",(?=\s*\w+=)", set_cookie):
            part = part.strip()
            if part:
                cookie_info = {
                    "raw": part[:200],
                    "secure": "secure" in part.lower(),
                    "httponly": "httponly" in part.lower(),
                    "samesite": "",
                }
                sm = re.search(r"samesite\s*=\s*(\w+)", part, re.I)
                if sm:
                    cookie_info["samesite"] = sm.group(1)
                result["cookies"].append(cookie_info)

    return result


def analyze_and_store(url: str, target_id: int, db_path=None) -> dict:
    """
    Analyze a page and store findings as recon_data for a target.

    Returns the full analysis result plus storage counts.
    """
    analysis = analyze_page(url)

    stored = {"tech": 0, "header": 0, "js_file": 0, "endpoint": 0, "parameter": 0, "other": 0}

    # Store technologies
    for tech in analysis["technologies"]:
        rid = add_recon(target_id, "tech", tech["name"],
                        source_tool="analyzer", raw_output=tech.get("evidence", ""),
                        db_path=db_path)
        if rid:
            stored["tech"] += 1

    # Store security header findings (missing headers are notable)
    for hdr in analysis["security_headers"]["missing"]:
        rid = add_recon(target_id, "header", f"[missing] {hdr}",
                        source_tool="analyzer", raw_output=f"Security header not set on {url}",
                        db_path=db_path)
        if rid:
            stored["header"] += 1

    # Store JS files
    for js_url in analysis["js_files"]:
        rid = add_recon(target_id, "js_file", js_url,
                        source_tool="analyzer", db_path=db_path)
        if rid:
            stored["js_file"] += 1

    # Store endpoints
    ep_count = bulk_add_recon(
        target_id, "endpoint",
        analysis["endpoints"],
        source_tool="analyzer", db_path=db_path,
    )
    stored["endpoint"] = ep_count

    # Store form parameters
    for form in analysis["forms"]:
        for inp in form["inputs"]:
            if inp["name"]:
                context = form["action"] or url
                rid = add_recon(target_id, "parameter",
                                f"{inp['name']} ({context})",
                                source_tool="analyzer",
                                raw_output=f"type={inp['type']}, form_method={form['method']}",
                                db_path=db_path)
                if rid:
                    stored["parameter"] += 1

    # Store interesting comments as 'other'
    for comment in analysis["comments"][:20]:
        rid = add_recon(target_id, "other", f"[html_comment] {comment[:200]}",
                        source_tool="analyzer", db_path=db_path)
        if rid:
            stored["other"] += 1

    # Store meta leaks
    for leak in analysis["meta_leaks"]:
        add_recon(target_id, "other", f"[meta:{leak['name']}] {leak['content']}",
                  source_tool="analyzer", db_path=db_path)

    log_action("page_analysis", "recon", None, {
        "target_id": target_id,
        "url": url,
        "technologies": len(analysis["technologies"]),
        "missing_headers": len(analysis["security_headers"]["missing"]),
        "forms": len(analysis["forms"]),
        "js_files": len(analysis["js_files"]),
        "endpoints": len(analysis["endpoints"]),
    }, db_path)

    analysis["stored"] = stored
    return analysis


def format_report(analysis: dict) -> str:
    """Format an analysis result as a human-readable text report."""
    lines = []
    lines.append(f"Page Analysis: {analysis['url']}")
    lines.append("=" * 60)

    if analysis.get("title"):
        lines.append(f"Title: {analysis['title']}")

    if analysis.get("errors"):
        for e in analysis["errors"]:
            lines.append(f"ERROR: {e}")
        return "\n".join(lines)

    # Technologies
    if analysis["technologies"]:
        lines.append(f"\nTechnologies ({len(analysis['technologies'])}):")
        for t in analysis["technologies"]:
            ev = f" — {t['evidence']}" if t.get("evidence") else ""
            lines.append(f"  • {t['name']} (via {t['source']}){ev}")

    # Security headers
    missing = analysis["security_headers"]["missing"]
    present = analysis["security_headers"]["present"]
    lines.append(f"\nSecurity Headers ({len(present)} present, {len(missing)} missing):")
    for hdr, val in present.items():
        lines.append(f"  ✓ {hdr}: {val[:80]}")
    for hdr in missing:
        lines.append(f"  ✗ {hdr}")

    # Forms
    if analysis["forms"]:
        lines.append(f"\nForms ({len(analysis['forms'])}):")
        for i, form in enumerate(analysis["forms"], 1):
            lines.append(f"  Form #{i}: {form['method']} → {form['action'] or '(same page)'}")
            for inp in form["inputs"]:
                val_hint = f" = {inp['value']}" if inp["value"] else ""
                lines.append(f"    [{inp['type']}] {inp['name'] or '(unnamed)'}{val_hint}")

    # JS files
    if analysis["js_files"]:
        lines.append(f"\nJavaScript Files ({len(analysis['js_files'])}):")
        for js in analysis["js_files"][:30]:
            lines.append(f"  • {js}")

    # Comments
    if analysis["comments"]:
        lines.append(f"\nHTML Comments ({len(analysis['comments'])}):")
        for c in analysis["comments"][:15]:
            lines.append(f"  <!-- {c[:120]} -->")

    # Meta leaks
    if analysis["meta_leaks"]:
        lines.append(f"\nMeta Tag Leaks ({len(analysis['meta_leaks'])}):")
        for leak in analysis["meta_leaks"]:
            lines.append(f"  • {leak['name']}: {leak['content']}")

    # Cookies
    if analysis["cookies"]:
        lines.append(f"\nCookies ({len(analysis['cookies'])}):")
        for c in analysis["cookies"]:
            flags = []
            if not c["secure"]:
                flags.append("NO Secure")
            if not c["httponly"]:
                flags.append("NO HttpOnly")
            if not c["samesite"]:
                flags.append("NO SameSite")
            flag_str = f"  ⚠ {', '.join(flags)}" if flags else "  ✓ Good flags"
            lines.append(f"  • {c['raw'][:80]}")
            lines.append(f"    {flag_str}")

    # Endpoints
    if analysis["endpoints"]:
        lines.append(f"\nDiscovered Endpoints ({len(analysis['endpoints'])}):")
        for ep in analysis["endpoints"][:40]:
            lines.append(f"  • {ep}")

    # Links summary
    links = analysis.get("links", {})
    int_count = len(links.get("internal", []))
    ext_count = len(links.get("external", []))
    lines.append(f"\nLinks: {int_count} internal, {ext_count} external")

    # Storage summary
    if "stored" in analysis:
        stored = analysis["stored"]
        total = sum(stored.values())
        lines.append(f"\nStored {total} new recon entries:")
        for dtype, count in stored.items():
            if count:
                lines.append(f"  • {dtype}: {count}")

    return "\n".join(lines)
