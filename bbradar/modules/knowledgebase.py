"""
Knowledge Base — External vulnerability databases.

Integrates CWE (MITRE), CAPEC (MITRE), Bugcrowd VRT, Nuclei templates,
NVD CVE data, CISA KEV (Known Exploited Vulnerabilities), and FIRST EPSS
(Exploit Prediction Scoring) into a local searchable knowledge base. Uses
conditional HTTP requests (ETag / If-Modified-Since) and minimum sync
intervals to avoid redundant downloads.

Sources:
    CWE    — Common Weakness Enumeration          (MITRE, quarterly)
    CAPEC  — Common Attack Pattern Enumeration     (MITRE, quarterly)
    VRT    — Vulnerability Rating Taxonomy         (Bugcrowd, open-source)
    Nuclei — Detection templates                   (ProjectDiscovery, frequent)
    CVE    — National Vulnerability Database       (NIST NVD API 2.0)
    KEV    — Known Exploited Vulnerabilities       (CISA, daily)
    EPSS   — Exploit Prediction Scoring System     (FIRST.org, daily)
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

from ..core.database import get_connection, init_db
from ..core.config import load_config


# ═══════════════════════════════════════════════════════════════════
# Source configuration
# ═══════════════════════════════════════════════════════════════════

SOURCES = {
    "cwe": {
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "description": "MITRE CWE — Common Weakness Enumeration",
        "min_sync_hours": 168,  # weekly — CWE updates quarterly
    },
    "capec": {
        "url": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "description": "MITRE CAPEC — Common Attack Pattern Enumeration",
        "min_sync_hours": 168,
    },
    "vrt": {
        "url": "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/main/vulnerability-rating-taxonomy.json",
        "description": "Bugcrowd Vulnerability Rating Taxonomy",
        "min_sync_hours": 72,  # every 3 days
    },
    "nuclei": {
        "repo": "https://github.com/projectdiscovery/nuclei-templates.git",
        "description": "ProjectDiscovery Nuclei Templates",
        "min_sync_hours": 24,
    },
    "cve": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "description": "NVD — NIST National Vulnerability Database (CVEs)",
        "min_sync_hours": 6,  # check every 6h, incremental
    },
    "kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "CISA KEV — Known Exploited Vulnerabilities",
        "min_sync_hours": 12,
    },
    "epss": {
        "url": "https://api.first.org/data/v1/epss?envelope=true&pretty=false",
        "description": "FIRST EPSS — Exploit Prediction Scoring System",
        "min_sync_hours": 24,
    },
}

USER_AGENT = "BBRadar/0.5.2 (Bug Bounty Assessment Platform)"


def _kb_dir() -> Path:
    """Return (and create) the KB cache directory."""
    cfg = load_config()
    d = Path(cfg.get("data_dir", Path.home() / ".bbradar")) / "kb"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


# ═══════════════════════════════════════════════════════════════════
# HTTP helpers — conditional fetching
# ═══════════════════════════════════════════════════════════════════

def _fetch(url: str, etag: str = None, last_modified: str = None,
           timeout: int = 120) -> tuple[bytes | None, str | None, str | None]:
    """
    Fetch a URL with conditional headers.

    Returns (data, new_etag, new_last_modified).
    data is None if the server returned 304 Not Modified.
    """
    req = Request(url)
    req.add_header("User-Agent", USER_AGENT)
    if etag:
        req.add_header("If-None-Match", etag)
    if last_modified:
        req.add_header("If-Modified-Since", last_modified)

    try:
        resp = urlopen(req, timeout=timeout)
        data = resp.read()
        new_etag = resp.headers.get("ETag")
        new_lm = resp.headers.get("Last-Modified")
        return data, new_etag, new_lm
    except HTTPError as e:
        if e.code == 304:
            return None, etag, last_modified
        raise


def _file_hash(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


# ═══════════════════════════════════════════════════════════════════
# Sync-log helpers
# ═══════════════════════════════════════════════════════════════════

def _get_sync_info(source: str, db_path=None) -> dict | None:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM kb_sync WHERE source = ?", (source,)).fetchone()
        return dict(row) if row else None


def _set_sync_info(source: str, record_count: int, etag: str = None,
                   last_modified: str = None, file_hash: str = None, db_path=None):
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO kb_sync (source, last_sync, etag, last_modified, record_count, file_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_sync = excluded.last_sync,
                etag = excluded.etag,
                last_modified = excluded.last_modified,
                record_count = excluded.record_count,
                file_hash = excluded.file_hash
        """, (source, now, etag, last_modified, record_count, file_hash))


def _should_skip(source: str, force: bool = False, db_path=None) -> bool:
    """Check if we should skip syncing (recently synced)."""
    if force:
        return False
    info = _get_sync_info(source, db_path)
    if not info or not info.get("last_sync"):
        return False
    min_hours = SOURCES[source].get("min_sync_hours", 24)
    last = datetime.fromisoformat(info["last_sync"])
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last < timedelta(hours=min_hours)


# ═══════════════════════════════════════════════════════════════════
# CWE Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_cwe(force: bool = False, db_path=None, callback=None) -> dict:
    """Download and parse the MITRE CWE database."""
    source = "cwe"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback(f"  Checking CWE database...")

    info = _get_sync_info(source, db_path) or {}
    url = SOURCES[source]["url"]

    try:
        data, new_etag, new_lm = _fetch(url, info.get("etag"), info.get("last_modified"))
    except (HTTPError, URLError) as e:
        result["status"] = "error"
        result["reason"] = str(e)
        return result

    if data is None:
        if callback:
            callback(f"  CWE: not modified (304)")
        result["status"] = "not_modified"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        # Update last_sync timestamp even on 304
        _set_sync_info(source, result["records"], new_etag, new_lm,
                       info.get("file_hash"), db_path)
        return result

    h = _file_hash(data)
    if h == info.get("file_hash"):
        if callback:
            callback(f"  CWE: content unchanged (hash match)")
        result["status"] = "unchanged"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm, h, db_path)
        return result

    if callback:
        callback(f"  Parsing CWE XML ({len(data) // 1024}KB compressed)...")

    # Extract XML from zip
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_names:
            result["status"] = "error"
            result["reason"] = "no XML found in zip"
            return result
        xml_data = zf.read(xml_names[0])

    count = _parse_cwe_xml(xml_data, db_path, callback)
    _set_sync_info(source, count, new_etag, new_lm, h, db_path)

    result["status"] = "updated"
    result["records"] = count
    return result


def _parse_cwe_xml(xml_data: bytes, db_path=None, callback=None) -> int:
    """Parse CWE XML using iterparse for memory efficiency."""
    # Detect namespace
    ns = ""
    for event, elem in ET.iterparse(io.BytesIO(xml_data), events=("start",)):
        tag = elem.tag
        if "}" in tag:
            ns = tag.split("}")[0] + "}"
        break

    def _tag(name):
        return f"{ns}{name}"

    count = 0
    rows = []

    for event, elem in ET.iterparse(io.BytesIO(xml_data), events=("end",)):
        if elem.tag != _tag("Weakness"):
            continue

        cwe_id = elem.get("ID", "")
        name = elem.get("Name", "")
        abstraction = elem.get("Abstraction", "")

        desc_el = elem.find(_tag("Description"))
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        ext_el = elem.find(_tag("Extended_Description"))
        extended = _flatten_text(ext_el) if ext_el is not None else ""

        # Consequences
        consequences = []
        for c in elem.findall(f".//{_tag('Consequence')}"):
            scopes = [s.text for s in c.findall(_tag("Scope")) if s.text]
            impacts = [i.text for i in c.findall(_tag("Impact")) if i.text]
            if scopes or impacts:
                consequences.append({"scope": scopes, "impact": impacts})

        # Mitigations
        mitigations = []
        for m in elem.findall(f".//{_tag('Mitigation')}"):
            phase_el = m.find(_tag("Phase"))
            desc_el2 = m.find(_tag("Description"))
            mit = {}
            if phase_el is not None and phase_el.text:
                mit["phase"] = phase_el.text
            if desc_el2 is not None:
                mit["description"] = _flatten_text(desc_el2)
            if mit:
                mitigations.append(mit)

        # Detection methods
        detections = []
        for d in elem.findall(f".//{_tag('Detection_Method')}"):
            method_el = d.find(_tag("Method"))
            det_desc = d.find(_tag("Description"))
            det = {}
            if method_el is not None and method_el.text:
                det["method"] = method_el.text
            if det_desc is not None:
                det["description"] = _flatten_text(det_desc)
            if det:
                detections.append(det)

        # Related CWEs
        related = []
        for r in elem.findall(f".//{_tag('Related_Weakness')}"):
            rel_id = r.get("CWE_ID", "")
            nature = r.get("Nature", "")
            if rel_id:
                related.append({"cwe_id": rel_id, "nature": nature})

        # OWASP mappings
        owasp = []
        for t in elem.findall(f".//{_tag('Taxonomy_Mapping')}"):
            tax_name = t.get("Taxonomy_Name", "")
            if "OWASP" in tax_name:
                eid = t.find(_tag("Entry_ID"))
                ename = t.find(_tag("Entry_Name"))
                entry = {"taxonomy": tax_name}
                if eid is not None and eid.text:
                    entry["id"] = eid.text
                if ename is not None and ename.text:
                    entry["name"] = ename.text
                owasp.append(entry)

        # Related CAPEC IDs
        capec_ids = []
        for ratt in elem.findall(f".//{_tag('Related_Attack_Pattern')}"):
            cid = ratt.get("CAPEC_ID", "")
            if cid:
                capec_ids.append(cid)

        rows.append((
            f"CWE-{cwe_id}", name, description, extended, abstraction,
            json.dumps(consequences) if consequences else None,
            json.dumps(mitigations) if mitigations else None,
            json.dumps(detections) if detections else None,
            json.dumps(related) if related else None,
            json.dumps(owasp) if owasp else None,
            json.dumps(capec_ids) if capec_ids else None,
        ))

        count += 1
        elem.clear()  # free memory

        # Batch insert every 500 rows
        if len(rows) >= 500:
            _insert_cwe_batch(rows, db_path)
            if callback:
                callback(f"    parsed {count} CWEs...")
            rows = []

    if rows:
        _insert_cwe_batch(rows, db_path)

    if callback:
        callback(f"  CWE: {count} weaknesses loaded")
    return count


def _insert_cwe_batch(rows, db_path=None):
    with get_connection(db_path) as conn:
        conn.executemany("""
            INSERT INTO kb_cwe (cwe_id, name, description, extended_description,
                                abstraction, consequences, mitigations, detection_methods,
                                related_cwes, owasp_mappings, capec_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cwe_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                extended_description = excluded.extended_description,
                abstraction = excluded.abstraction,
                consequences = excluded.consequences,
                mitigations = excluded.mitigations,
                detection_methods = excluded.detection_methods,
                related_cwes = excluded.related_cwes,
                owasp_mappings = excluded.owasp_mappings,
                capec_ids = excluded.capec_ids
        """, rows)


def _flatten_text(elem) -> str:
    """Recursively extract all text from an element and its children."""
    parts = []
    if elem.text:
        parts.append(elem.text.strip())
    for child in elem:
        parts.append(_flatten_text(child))
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)


# ═══════════════════════════════════════════════════════════════════
# CAPEC Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_capec(force: bool = False, db_path=None, callback=None) -> dict:
    """Download and parse the MITRE CAPEC database."""
    source = "capec"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback(f"  Checking CAPEC database...")

    info = _get_sync_info(source, db_path) or {}
    url = SOURCES[source]["url"]

    try:
        data, new_etag, new_lm = _fetch(url, info.get("etag"), info.get("last_modified"))
    except (HTTPError, URLError) as e:
        result["status"] = "error"
        result["reason"] = str(e)
        return result

    if data is None:
        if callback:
            callback(f"  CAPEC: not modified (304)")
        result["status"] = "not_modified"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm,
                       info.get("file_hash"), db_path)
        return result

    h = _file_hash(data)
    if h == info.get("file_hash"):
        if callback:
            callback(f"  CAPEC: content unchanged (hash match)")
        result["status"] = "unchanged"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm, h, db_path)
        return result

    if callback:
        callback(f"  Parsing CAPEC XML ({len(data) // 1024}KB)...")

    count = _parse_capec_xml(data, db_path, callback)
    _set_sync_info(source, count, new_etag, new_lm, h, db_path)

    result["status"] = "updated"
    result["records"] = count
    return result


def _parse_capec_xml(xml_data: bytes, db_path=None, callback=None) -> int:
    """Parse CAPEC XML using iterparse."""
    ns = ""
    for event, elem in ET.iterparse(io.BytesIO(xml_data), events=("start",)):
        tag = elem.tag
        if "}" in tag:
            ns = tag.split("}")[0] + "}"
        break

    def _tag(name):
        return f"{ns}{name}"

    count = 0
    rows = []

    for event, elem in ET.iterparse(io.BytesIO(xml_data), events=("end",)):
        if elem.tag != _tag("Attack_Pattern"):
            continue

        capec_id = elem.get("ID", "")
        name = elem.get("Name", "")

        desc_el = elem.find(_tag("Description"))
        description = _flatten_text(desc_el) if desc_el is not None else ""

        likelihood_el = elem.find(_tag("Likelihood_Of_Attack"))
        likelihood = likelihood_el.text.strip() if likelihood_el is not None and likelihood_el.text else ""

        severity_el = elem.find(_tag("Typical_Severity"))
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else ""

        prereqs = []
        for p in elem.findall(f".//{_tag('Prerequisite')}"):
            if p.text:
                prereqs.append(p.text.strip())

        mitigations = []
        for m in elem.findall(f".//{_tag('Mitigation')}"):
            mit_text = _flatten_text(m)
            if mit_text:
                mitigations.append(mit_text)

        related_cwes = []
        for r in elem.findall(f".//{_tag('Related_Weakness')}"):
            cid = r.get("CWE_ID", "")
            if cid:
                related_cwes.append(f"CWE-{cid}")

        rows.append((
            f"CAPEC-{capec_id}", name, description, likelihood, severity,
            json.dumps(prereqs) if prereqs else None,
            json.dumps(mitigations) if mitigations else None,
            json.dumps(related_cwes) if related_cwes else None,
        ))

        count += 1
        elem.clear()

        if len(rows) >= 500:
            _insert_capec_batch(rows, db_path)
            if callback:
                callback(f"    parsed {count} attack patterns...")
            rows = []

    if rows:
        _insert_capec_batch(rows, db_path)

    if callback:
        callback(f"  CAPEC: {count} attack patterns loaded")
    return count


def _insert_capec_batch(rows, db_path=None):
    with get_connection(db_path) as conn:
        conn.executemany("""
            INSERT INTO kb_capec (capec_id, name, description, likelihood, severity,
                                  prerequisites, mitigations, related_cwes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(capec_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                likelihood = excluded.likelihood,
                severity = excluded.severity,
                prerequisites = excluded.prerequisites,
                mitigations = excluded.mitigations,
                related_cwes = excluded.related_cwes
        """, rows)


# ═══════════════════════════════════════════════════════════════════
# Bugcrowd VRT Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_vrt(force: bool = False, db_path=None, callback=None) -> dict:
    """Download and parse the Bugcrowd VRT."""
    source = "vrt"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback(f"  Checking Bugcrowd VRT...")

    info = _get_sync_info(source, db_path) or {}
    url = SOURCES[source]["url"]

    try:
        data, new_etag, new_lm = _fetch(url, info.get("etag"), info.get("last_modified"))
    except (HTTPError, URLError):
        # Try master branch as fallback
        try:
            alt_url = url.replace("/main/", "/master/")
            data, new_etag, new_lm = _fetch(alt_url, info.get("etag"), info.get("last_modified"))
        except (HTTPError, URLError) as e2:
            result["status"] = "error"
            result["reason"] = str(e2)
            return result

    if data is None:
        if callback:
            callback(f"  VRT: not modified (304)")
        result["status"] = "not_modified"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm,
                       info.get("file_hash"), db_path)
        return result

    h = _file_hash(data)
    if h == info.get("file_hash"):
        if callback:
            callback(f"  VRT: content unchanged")
        result["status"] = "unchanged"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm, h, db_path)
        return result

    if callback:
        callback(f"  Parsing Bugcrowd VRT...")

    vrt_data = json.loads(data)
    count = _parse_vrt(vrt_data, db_path)
    _set_sync_info(source, count, new_etag, new_lm, h, db_path)

    if callback:
        callback(f"  VRT: {count} entries loaded")
    result["status"] = "updated"
    result["records"] = count
    return result


def _parse_vrt(vrt_data: dict, db_path=None) -> int:
    """Parse VRT JSON tree into flat DB rows."""
    rows = []
    content = vrt_data.get("content", vrt_data) if isinstance(vrt_data, dict) else vrt_data

    def _walk(nodes, parent_path="", category=""):
        for node in nodes:
            node_id = node.get("id", "")
            name = node.get("name", node_id)
            path = f"{parent_path}.{node_id}" if parent_path else node_id
            priority = node.get("priority")
            cat = category or name

            rows.append((path, name, priority, cat, parent_path or None))

            children = node.get("children", [])
            if children:
                _walk(children, path, cat)

    if isinstance(content, list):
        _walk(content)
    elif isinstance(content, dict) and "content" in content:
        _walk(content["content"])

    with get_connection(db_path) as conn:
        conn.executemany("""
            INSERT INTO kb_vrt (path, name, priority, category, parent_path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                name = excluded.name,
                priority = excluded.priority,
                category = excluded.category,
                parent_path = excluded.parent_path
        """, rows)

    return len(rows)


# ═══════════════════════════════════════════════════════════════════
# Nuclei Templates Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def _nuclei_dir() -> Path:
    """Find or determine the nuclei templates directory."""
    # Check common locations
    candidates = [
        Path.home() / "nuclei-templates",
        Path("/opt/nuclei-templates"),
        Path.home() / ".local" / "nuclei-templates",
    ]
    for c in candidates:
        if c.is_dir() and (c / ".git").is_dir():
            return c

    # Default to our KB cache
    return _kb_dir() / "nuclei-templates"


def sync_nuclei(force: bool = False, db_path=None, callback=None) -> dict:
    """Sync Nuclei templates from git (shallow clone / pull)."""
    source = "nuclei"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    # Check if git is available
    if not shutil.which("git"):
        result["status"] = "error"
        result["reason"] = "git not found — install git to sync nuclei templates"
        return result

    tpl_dir = _nuclei_dir()
    repo_url = SOURCES[source]["repo"]

    if (tpl_dir / ".git").is_dir():
        # Already cloned — just pull
        if callback:
            callback(f"  Updating nuclei templates ({tpl_dir})...")
        try:
            proc = subprocess.run(
                ["git", "-C", str(tpl_dir), "pull", "--ff-only", "--depth=1"],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0 and "Already up to date" not in (proc.stdout + proc.stderr):
                # Try fetch + reset for shallow repos
                subprocess.run(
                    ["git", "-C", str(tpl_dir), "fetch", "--depth=1", "origin"],
                    capture_output=True, timeout=300,
                )
                subprocess.run(
                    ["git", "-C", str(tpl_dir), "reset", "--hard", "origin/main"],
                    capture_output=True, timeout=60,
                )
        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["reason"] = "git pull timed out"
            return result
    else:
        # Fresh shallow clone
        if callback:
            callback(f"  Cloning nuclei templates (shallow, one-time)...")
            callback(f"    → {repo_url}")
        tpl_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", "--single-branch", repo_url, str(tpl_dir)],
                capture_output=True, timeout=600,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            result["status"] = "error"
            result["reason"] = f"git clone failed: {e.stderr[:200] if e.stderr else 'unknown error'}"
            return result
        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["reason"] = "git clone timed out (10 min)"
            return result

    if callback:
        callback(f"  Parsing nuclei templates...")

    count = _parse_nuclei_templates(tpl_dir, db_path, callback)
    _set_sync_info(source, count, db_path=db_path)

    result["status"] = "updated"
    result["records"] = count
    return result


def _parse_nuclei_templates(tpl_dir: Path, db_path=None, callback=None) -> int:
    """Walk nuclei-templates directory and extract metadata from YAML info blocks."""
    count = 0
    rows = []

    # Only parse template yaml files, skip helpers/workflows/etc
    scan_dirs = ["http", "dns", "file", "headless", "network", "ssl", "websocket",
                 "javascript", "code", "multi", "cloud", "dast"]

    for scan_dir_name in scan_dirs:
        scan_path = tpl_dir / scan_dir_name
        if not scan_path.is_dir():
            continue
        for yaml_file in scan_path.rglob("*.yaml"):
            try:
                row = _parse_nuclei_file(yaml_file)
                if row:
                    rows.append(row)
                    count += 1
            except Exception:
                continue  # skip malformed files

            if len(rows) >= 500:
                _insert_nuclei_batch(rows, db_path)
                if callback and count % 2000 == 0:
                    callback(f"    parsed {count} templates...")
                rows = []

    if rows:
        _insert_nuclei_batch(rows, db_path)

    if callback:
        callback(f"  Nuclei: {count} templates loaded")
    return count


def _parse_nuclei_file(filepath: Path) -> tuple | None:
    """Extract metadata from a single nuclei template YAML file."""
    # Read only first 80 lines for the info block (avoid loading huge request bodies)
    lines = []
    with open(filepath, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= 80:
                break
            lines.append(line)

    text = "".join(lines)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None

    if not isinstance(data, dict):
        return None

    info = data.get("info")
    if not info or not isinstance(info, dict):
        return None

    template_id = data.get("id", filepath.stem)
    name = info.get("name", "")
    severity = info.get("severity", "")
    description = info.get("description", "")
    remediation = info.get("remediation", "")
    tags = info.get("tags", "")

    classification = info.get("classification", {}) or {}
    cwe_id = ""
    cvss_score = None
    cvss_vector = ""

    if isinstance(classification, dict):
        cwe_raw = classification.get("cwe-id", "")
        if isinstance(cwe_raw, list):
            cwe_id = cwe_raw[0] if cwe_raw else ""
        else:
            cwe_id = str(cwe_raw) if cwe_raw else ""
        cvss_score = classification.get("cvss-score")
        cvss_vector = classification.get("cvss-metrics", "")

    refs = info.get("reference", [])
    if isinstance(refs, list):
        refs_json = json.dumps(refs) if refs else None
    elif isinstance(refs, str):
        refs_json = json.dumps([refs]) if refs else None
    else:
        refs_json = None

    return (
        template_id, name, severity, description or "", remediation or "",
        tags if isinstance(tags, str) else ",".join(tags) if isinstance(tags, list) else "",
        cwe_id, cvss_score, cvss_vector or "", refs_json,
        str(filepath),
    )


def _insert_nuclei_batch(rows, db_path=None):
    with get_connection(db_path) as conn:
        conn.executemany("""
            INSERT INTO kb_nuclei (template_id, name, severity, description, remediation,
                                   tags, cwe_id, cvss_score, cvss_vector, reference_urls, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(template_id) DO UPDATE SET
                name = excluded.name,
                severity = excluded.severity,
                description = excluded.description,
                remediation = excluded.remediation,
                tags = excluded.tags,
                cwe_id = excluded.cwe_id,
                cvss_score = excluded.cvss_score,
                cvss_vector = excluded.cvss_vector,
                reference_urls = excluded.reference_urls,
                file_path = excluded.file_path
        """, rows)


# ═══════════════════════════════════════════════════════════════════
# NVD CVE Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_cve(force: bool = False, db_path=None, callback=None) -> dict:
    """
    Download CVE data from NVD API 2.0.

    Does incremental sync: on first run fetches recent CVEs (last 120 days);
    on subsequent runs fetches only CVEs modified since last sync.
    NVD rate limits to ~5 requests per 30 seconds without an API key.
    """
    import time as _time

    source = "cve"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback("  Checking NVD CVE database...")

    info = _get_sync_info(source, db_path) or {}
    base_url = SOURCES[source]["url"]

    # Build date range for incremental sync
    if info.get("last_sync"):
        # Incremental: fetch CVEs modified since last sync
        last = info["last_sync"][:19].replace("T", " ").replace(" ", "T")
        params = f"lastModStartDate={last}Z&lastModEndDate={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')}Z"
    else:
        # Initial: last 120 days of CVEs
        start = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        params = f"pubStartDate={start}Z&pubEndDate={end}Z"

    total_results = 0
    start_index = 0
    batch_size = 2000
    total_count = 0

    while True:
        url = f"{base_url}?{params}&startIndex={start_index}&resultsPerPage={batch_size}"

        if callback:
            callback(f"    Fetching CVEs (offset {start_index})...")

        try:
            data, _, _ = _fetch(url, timeout=180)
        except (HTTPError, URLError) as e:
            if total_count == 0:
                result["status"] = "error"
                result["reason"] = str(e)
                return result
            break  # partial success

        if data is None:
            break

        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            result["status"] = "error"
            result["reason"] = "invalid JSON from NVD"
            return result

        vulnerabilities = payload.get("vulnerabilities", [])
        total_results = payload.get("totalResults", 0)

        if not vulnerabilities:
            break

        rows = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            row = _parse_nvd_cve(cve)
            if row:
                rows.append(row)

        if rows:
            _insert_cve_batch(rows, db_path)
            total_count += len(rows)

        start_index += len(vulnerabilities)
        if start_index >= total_results:
            break

        # NVD rate limit: ~5 requests per 30s without API key
        _time.sleep(6)

    # Get current total in DB
    with get_connection(db_path) as conn:
        db_total = conn.execute("SELECT COUNT(*) as c FROM kb_cve").fetchone()["c"]

    _set_sync_info(source, db_total, db_path=db_path)

    if total_count > 0:
        result["status"] = "updated"
        result["records"] = db_total
        result["new_cves"] = total_count
        if callback:
            callback(f"  CVE: {total_count} CVEs synced ({db_total} total in DB)")
    elif total_results == 0:
        result["status"] = "not_modified"
        result["records"] = db_total
        _set_sync_info(source, db_total, db_path=db_path)
        if callback:
            callback("  CVE: no new or modified CVEs")
    else:
        result["status"] = "unchanged"
        result["records"] = db_total

    return result


def _parse_nvd_cve(cve: dict) -> tuple | None:
    """Parse a single CVE entry from NVD API 2.0 format."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description (prefer English)
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        descs = cve.get("descriptions", [])
        description = descs[0].get("value", "") if descs else ""

    # CVSS v3.1 metrics
    cvss_score = None
    cvss_vector = None
    cvss_severity = None
    metrics = cve.get("metrics", {})
    for v31 in metrics.get("cvssMetricV31", []):
        cvss_data = v31.get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        cvss_severity = cvss_data.get("baseSeverity")
        break
    # Fall back to v3.0
    if cvss_score is None:
        for v30 in metrics.get("cvssMetricV30", []):
            cvss_data = v30.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_severity = cvss_data.get("baseSeverity")
            break

    # CWE IDs
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val != "CWE-noinfo":
                cwe_ids.append(val)

    # Affected products (CPE strings)
    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    products.append(cpe)

    # References
    refs = []
    for ref in cve.get("references", [])[:20]:
        refs.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", []),
        })

    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    return (
        cve_id, description,
        cvss_score, cvss_vector, cvss_severity,
        json.dumps(cwe_ids) if cwe_ids else None,
        json.dumps(products[:50]) if products else None,
        json.dumps(refs) if refs else None,
        published, modified,
    )


def _insert_cve_batch(rows, db_path=None):
    with get_connection(db_path) as conn:
        conn.executemany("""
            INSERT INTO kb_cve (cve_id, description, cvss_v31_score, cvss_v31_vector,
                                cvss_v31_severity, cwe_ids, affected_products,
                                "references", published_at, modified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = excluded.description,
                cvss_v31_score = excluded.cvss_v31_score,
                cvss_v31_vector = excluded.cvss_v31_vector,
                cvss_v31_severity = excluded.cvss_v31_severity,
                cwe_ids = excluded.cwe_ids,
                affected_products = excluded.affected_products,
                "references" = excluded."references",
                published_at = excluded.published_at,
                modified_at = excluded.modified_at,
                synced_at = datetime('now')
        """, rows)


# ═══════════════════════════════════════════════════════════════════
# CISA KEV Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_kev(force: bool = False, db_path=None, callback=None) -> dict:
    """Download and parse the CISA Known Exploited Vulnerabilities catalog."""
    source = "kev"
    result = {"source": source, "status": "skipped", "records": 0}

    if _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback("  Checking CISA KEV catalog...")

    info = _get_sync_info(source, db_path) or {}
    url = SOURCES[source]["url"]

    try:
        data, new_etag, new_lm = _fetch(url, info.get("etag"), info.get("last_modified"))
    except (HTTPError, URLError) as e:
        result["status"] = "error"
        result["reason"] = str(e)
        return result

    if data is None:
        if callback:
            callback("  KEV: not modified (304)")
        result["status"] = "not_modified"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm,
                       info.get("file_hash"), db_path)
        return result

    h = _file_hash(data)
    if h == info.get("file_hash"):
        if callback:
            callback("  KEV: content unchanged (hash match)")
        result["status"] = "unchanged"
        info2 = _get_sync_info(source, db_path)
        result["records"] = info2.get("record_count", 0) if info2 else 0
        _set_sync_info(source, result["records"], new_etag, new_lm, h, db_path)
        return result

    if callback:
        callback(f"  Parsing CISA KEV catalog ({len(data) // 1024}KB)...")

    try:
        catalog = json.loads(data)
    except json.JSONDecodeError:
        result["status"] = "error"
        result["reason"] = "invalid JSON from CISA"
        return result

    vulns = catalog.get("vulnerabilities", [])

    # Track which CVEs are newly added to KEV since our last sync
    existing_kev_cves = set()
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT cve_id FROM kb_kev").fetchall()
        existing_kev_cves = {r["cve_id"] for r in rows}

    new_kev_entries = []
    db_rows = []
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue
        db_rows.append((
            cve_id,
            v.get("vendorProject", ""),
            v.get("product", ""),
            v.get("vulnerabilityName", ""),
            v.get("shortDescription", ""),
            v.get("dateAdded", ""),
            v.get("dueDate", ""),
            v.get("requiredAction", ""),
            v.get("knownRansomwareCampaignUse", ""),
            v.get("notes", ""),
        ))
        if cve_id not in existing_kev_cves:
            new_kev_entries.append({
                "cve_id": cve_id,
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
            })

    # Batch insert
    for i in range(0, len(db_rows), 500):
        batch = db_rows[i:i + 500]
        with get_connection(db_path) as conn:
            conn.executemany("""
                INSERT INTO kb_kev (cve_id, vendor, product, name, description,
                                    date_added, due_date, required_action,
                                    known_ransomware, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    vendor = excluded.vendor,
                    product = excluded.product,
                    name = excluded.name,
                    description = excluded.description,
                    date_added = excluded.date_added,
                    due_date = excluded.due_date,
                    required_action = excluded.required_action,
                    known_ransomware = excluded.known_ransomware,
                    notes = excluded.notes,
                    synced_at = datetime('now')
            """, batch)

    count = len(db_rows)
    _set_sync_info(source, count, new_etag, new_lm, h, db_path)

    result["status"] = "updated"
    result["records"] = count
    if new_kev_entries:
        result["new_kev_entries"] = new_kev_entries
    if callback:
        new_msg = f" ({len(new_kev_entries)} new)" if new_kev_entries else ""
        callback(f"  KEV: {count} entries loaded{new_msg}")

    return result


# ═══════════════════════════════════════════════════════════════════
# EPSS Sync & Parse
# ═══════════════════════════════════════════════════════════════════

def sync_epss(force: bool = False, db_path=None, callback=None,
              cve_ids: list[str] | None = None) -> dict:
    """
    Sync EPSS scores from FIRST.org.

    If *cve_ids* are given, fetches scores only for those CVEs (up to 100).
    Otherwise, fetches scores for all CVEs in our kb_cve table that
    don't have EPSS data yet (or scores older than 7 days).
    """
    import time as _time

    source = "epss"
    result = {"source": source, "status": "skipped", "records": 0}

    if not cve_ids and _should_skip(source, force, db_path):
        info = _get_sync_info(source, db_path)
        result["records"] = info.get("record_count", 0) if info else 0
        result["reason"] = "recently synced"
        return result

    if callback:
        callback("  Checking EPSS scores...")

    base_url = "https://api.first.org/data/v1/epss"

    # If no explicit CVE list, find CVEs needing EPSS data
    if not cve_ids:
        with get_connection(db_path) as conn:
            # CVEs in our DB without EPSS scores, or with stale scores
            stale_cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            rows = conn.execute("""
                SELECT c.cve_id FROM kb_cve c
                LEFT JOIN kb_epss e ON c.cve_id = e.cve_id
                WHERE e.cve_id IS NULL OR e.synced_at < ?
                LIMIT 5000
            """, (stale_cutoff,)).fetchall()
            cve_ids = [r["cve_id"] for r in rows]

    if not cve_ids:
        result["status"] = "not_modified"
        with get_connection(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) as c FROM kb_epss").fetchone()["c"]
        result["records"] = count
        _set_sync_info(source, count, db_path=db_path)
        if callback:
            callback("  EPSS: all scores up to date")
        return result

    # Fetch in batches of 100 (EPSS API limit)
    total_fetched = 0
    batch_size = 100

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)
        url = f"{base_url}?cve={cve_param}"

        if callback and i > 0:
            callback(f"    Fetching EPSS scores ({i}/{len(cve_ids)})...")

        try:
            data, _, _ = _fetch(url, timeout=60)
        except (HTTPError, URLError) as e:
            if total_fetched == 0:
                result["status"] = "error"
                result["reason"] = str(e)
                return result
            break

        if data is None:
            continue

        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            continue

        rows = []
        model_version = payload.get("model_version", "")
        score_date = payload.get("score_date", "")

        for entry in payload.get("data", []):
            cve_id = entry.get("cve", "")
            if not cve_id:
                continue
            try:
                epss_score = float(entry.get("epss", 0))
                percentile = float(entry.get("percentile", 0))
            except (ValueError, TypeError):
                continue
            rows.append((cve_id, epss_score, percentile, model_version, score_date))

        if rows:
            with get_connection(db_path) as conn:
                conn.executemany("""
                    INSERT INTO kb_epss (cve_id, epss_score, percentile, model_version, score_date)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        epss_score = excluded.epss_score,
                        percentile = excluded.percentile,
                        model_version = excluded.model_version,
                        score_date = excluded.score_date,
                        synced_at = datetime('now')
                """, rows)
            total_fetched += len(rows)

        if i + batch_size < len(cve_ids):
            _time.sleep(1)  # be polite to API

    with get_connection(db_path) as conn:
        db_total = conn.execute("SELECT COUNT(*) as c FROM kb_epss").fetchone()["c"]

    _set_sync_info(source, db_total, db_path=db_path)

    result["status"] = "updated" if total_fetched > 0 else "not_modified"
    result["records"] = db_total
    if callback:
        callback(f"  EPSS: {total_fetched} scores fetched ({db_total} total)")

    return result


# ═══════════════════════════════════════════════════════════════════
# Sync All
# ═══════════════════════════════════════════════════════════════════

def sync_all(force: bool = False, sources: list[str] | None = None,
             db_path=None, callback=None) -> list[dict]:
    """Sync all (or selected) KB sources."""
    # Ensure KB schema exists
    init_db(db_path)

    sync_funcs = {
        "cwe": sync_cwe,
        "capec": sync_capec,
        "vrt": sync_vrt,
        "nuclei": sync_nuclei,
        "cve": sync_cve,
        "kev": sync_kev,
        "epss": sync_epss,
    }
    targets = sources or list(sync_funcs.keys())
    results = []

    for src in targets:
        func = sync_funcs.get(src)
        if not func:
            results.append({"source": src, "status": "error", "reason": f"unknown source '{src}'"})
            continue
        r = func(force=force, db_path=db_path, callback=callback)
        results.append(r)

    return results


# ═══════════════════════════════════════════════════════════════════
# Lookup & Search
# ═══════════════════════════════════════════════════════════════════

def get_sync_status(db_path=None) -> list[dict]:
    """Return sync status for all sources."""
    rows = []
    for src, meta in SOURCES.items():
        info = _get_sync_info(src, db_path)
        rows.append({
            "source": src,
            "description": meta["description"],
            "last_sync": info["last_sync"] if info else "never",
            "records": info["record_count"] if info else 0,
            "min_sync_hours": meta.get("min_sync_hours", 24),
        })
    return rows


def lookup_cwe(cwe_id: str, db_path=None) -> dict | None:
    """Look up a CWE by ID (accepts '79', 'CWE-79', 'cwe-79')."""
    cwe_id = cwe_id.upper().replace("CWE-", "").strip()
    cwe_id = f"CWE-{cwe_id}"
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM kb_cwe WHERE cwe_id = ?", (cwe_id,)).fetchone()
        if row:
            d = dict(row)
            for field in ("consequences", "mitigations", "detection_methods",
                          "related_cwes", "owasp_mappings", "capec_ids"):
                if d.get(field):
                    d[field] = json.loads(d[field])
            return d
    return None


def lookup_capec(capec_id: str, db_path=None) -> dict | None:
    """Look up a CAPEC by ID."""
    capec_id = capec_id.upper().replace("CAPEC-", "").strip()
    capec_id = f"CAPEC-{capec_id}"
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM kb_capec WHERE capec_id = ?", (capec_id,)).fetchone()
        if row:
            d = dict(row)
            for field in ("prerequisites", "mitigations", "related_cwes"):
                if d.get(field):
                    d[field] = json.loads(d[field])
            return d
    return None


def lookup_cve(cve_id: str, db_path=None) -> dict | None:
    """Look up a CVE by ID with KEV and EPSS data.

    Returns combined dict with CVE details, exploit status (KEV), and
    exploitation probability (EPSS). Accepts 'CVE-2024-1234' or '2024-1234'.
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    result = None
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM kb_cve WHERE cve_id = ?", (cve_id,)).fetchone()
        if row:
            result = dict(row)
            for field in ("cwe_ids", "affected_products", "references"):
                if result.get(field):
                    result[field] = json.loads(result[field])

            # Enrich with KEV data
            kev = conn.execute("SELECT * FROM kb_kev WHERE cve_id = ?", (cve_id,)).fetchone()
            if kev:
                result["kev"] = dict(kev)
                result["actively_exploited"] = True
            else:
                result["actively_exploited"] = False

            # Enrich with EPSS data
            epss = conn.execute("SELECT * FROM kb_epss WHERE cve_id = ?", (cve_id,)).fetchone()
            if epss:
                result["epss"] = dict(epss)
        else:
            # Try KEV-only lookup (some CVEs may not be in NVD yet)
            kev = conn.execute("SELECT * FROM kb_kev WHERE cve_id = ?", (cve_id,)).fetchone()
            if kev:
                result = {"cve_id": cve_id, "kev": dict(kev), "actively_exploited": True}
                result["description"] = kev["description"]

    return result


def browse_vrt(category: str = None, db_path=None) -> list[dict]:
    """List VRT entries, optionally filtered by category."""
    with get_connection(db_path) as conn:
        if category:
            rows = conn.execute(
                "SELECT * FROM kb_vrt WHERE category LIKE ? OR path LIKE ? ORDER BY path",
                (f"%{category}%", f"%{category}%"),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM kb_vrt WHERE parent_path IS NULL ORDER BY path"
            ).fetchall()
        return [dict(r) for r in rows]


def browse_vrt_children(parent_path: str, db_path=None) -> list[dict]:
    """List children of a VRT node."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM kb_vrt WHERE parent_path = ? ORDER BY path",
            (parent_path,),
        ).fetchall()
        return [dict(r) for r in rows]


def search_kb(query: str, db_path=None) -> dict:
    """
    Full-text search across all KB tables.

    Returns {"cwe": [...], "capec": [...], "vrt": [...], "nuclei": [...]}.
    """
    results = {"cwe": [], "capec": [], "vrt": [], "nuclei": [], "cve": [], "kev": []}
    q = f"%{query}%"

    with get_connection(db_path) as conn:
        # CWE
        rows = conn.execute("""
            SELECT cwe_id, name, description, abstraction FROM kb_cwe
            WHERE cwe_id LIKE ? OR name LIKE ? OR description LIKE ?
            LIMIT 25
        """, (q, q, q)).fetchall()
        results["cwe"] = [dict(r) for r in rows]

        # CAPEC
        rows = conn.execute("""
            SELECT capec_id, name, description, severity FROM kb_capec
            WHERE capec_id LIKE ? OR name LIKE ? OR description LIKE ?
            LIMIT 25
        """, (q, q, q)).fetchall()
        results["capec"] = [dict(r) for r in rows]

        # VRT
        rows = conn.execute("""
            SELECT path, name, priority, category FROM kb_vrt
            WHERE path LIKE ? OR name LIKE ? OR category LIKE ?
            LIMIT 25
        """, (q, q, q)).fetchall()
        results["vrt"] = [dict(r) for r in rows]

        # Nuclei
        rows = conn.execute("""
            SELECT template_id, name, severity, cwe_id, tags FROM kb_nuclei
            WHERE template_id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?
            LIMIT 25
        """, (q, q, q, q)).fetchall()
        results["nuclei"] = [dict(r) for r in rows]

        # CVE
        rows = conn.execute("""
            SELECT cve_id, description, cvss_v31_score, cvss_v31_severity,
                   published_at FROM kb_cve
            WHERE cve_id LIKE ? OR description LIKE ?
            LIMIT 25
        """, (q, q)).fetchall()
        results["cve"] = [dict(r) for r in rows]

        # KEV
        rows = conn.execute("""
            SELECT cve_id, vendor, product, name, description,
                   date_added FROM kb_kev
            WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ?
                  OR name LIKE ? OR description LIKE ?
            LIMIT 25
        """, (q, q, q, q, q)).fetchall()
        results["kev"] = [dict(r) for r in rows]

    return results


def search_nuclei(query: str = None, severity: str = None, cwe: str = None,
                  tag: str = None, limit: int = 50, db_path=None) -> list[dict]:
    """Search nuclei templates with filters."""
    conditions = []
    params = []

    if query:
        conditions.append("(template_id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?)")
        q = f"%{query}%"
        params.extend([q, q, q, q])
    if severity:
        conditions.append("severity = ?")
        params.append(severity.lower())
    if cwe:
        cwe_clean = cwe.upper().replace("CWE-", "").strip()
        conditions.append("(cwe_id LIKE ?)")
        params.append(f"%{cwe_clean}%")
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f"%{tag}%")

    where = " AND ".join(conditions) if conditions else "1=1"
    sql = f"SELECT * FROM kb_nuclei WHERE {where} ORDER BY severity, name LIMIT ?"
    params.append(limit)

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def enrich_vuln(vuln: dict, db_path=None) -> dict:
    """
    Given a vulnerability dict, enrich it with KB data.

    Looks at the description for CWE references and pulls in
    full CWE details, related CAPEC patterns, and VRT priority.
    Returns an enrichment dict (does not modify original).
    """
    enrichment = {}

    import re

    # Try to find CWE ID from description or vuln data
    cwe_id = None
    desc = vuln.get("description", "") or ""

    cwe_match = re.search(r"CWE-(\d+)", desc, re.IGNORECASE)
    if cwe_match:
        cwe_id = cwe_match.group(1)

    if cwe_id:
        cwe = lookup_cwe(cwe_id, db_path)
        if cwe:
            enrichment["cwe"] = cwe

            # Get related CAPEC patterns
            capec_ids = cwe.get("capec_ids", [])
            if capec_ids:
                patterns = []
                for cid in capec_ids[:10]:
                    capec = lookup_capec(cid, db_path)
                    if capec:
                        patterns.append(capec)
                if patterns:
                    enrichment["related_capec"] = patterns

    # Search nuclei for related templates
    vuln_type = vuln.get("vuln_type", "")
    if vuln_type:
        nuclei_results = search_nuclei(tag=vuln_type, limit=10, db_path=db_path)
        if nuclei_results:
            enrichment["related_nuclei"] = nuclei_results

    # CVE / KEV / EPSS enrichment
    cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", desc, re.IGNORECASE)
    # Also check explicit cve_id field
    explicit_cve = vuln.get("cve_id") or vuln.get("cve") or ""
    if explicit_cve and explicit_cve not in cve_ids:
        cve_ids.insert(0, explicit_cve)

    if cve_ids:
        cve_details = []
        for cveid in cve_ids[:5]:
            detail = lookup_cve(cveid, db_path)
            if detail:
                cve_details.append(detail)
        if cve_details:
            enrichment["cve_details"] = cve_details
            # Surface exploit status at top level
            if any(d.get("actively_exploited") for d in cve_details):
                enrichment["actively_exploited"] = True
                enrichment["kev_entries"] = [
                    d["kev"] for d in cve_details if d.get("kev")
                ]
            # Surface highest EPSS score
            epss_scores = [
                d["epss"]["epss_score"]
                for d in cve_details if d.get("epss")
            ]
            if epss_scores:
                enrichment["max_epss_score"] = max(epss_scores)

    return enrichment


def kb_stats(db_path=None) -> dict:
    """Return record counts for all KB tables."""
    stats = {}
    with get_connection(db_path) as conn:
        for table in ("kb_cwe", "kb_capec", "kb_vrt", "kb_nuclei",
                      "kb_cve", "kb_kev", "kb_epss"):
            row = conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()
            stats[table.replace("kb_", "")] = row["c"] if row else 0
    return stats
