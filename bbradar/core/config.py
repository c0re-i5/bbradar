"""
Configuration management for BBRadar.

Stores settings in ~/.bbradar/config.yaml. All paths and preferences
are configurable; sensible defaults are provided.
"""

import copy
import os
from pathlib import Path

import yaml

DEFAULT_DATA_DIR = Path.home() / ".bbradar"
CONFIG_PATH = DEFAULT_DATA_DIR / "config.yaml"

DEFAULTS = {
    "data_dir": str(DEFAULT_DATA_DIR),
    "evidence_dir": str(DEFAULT_DATA_DIR / "evidence"),
    "reports_dir": str(DEFAULT_DATA_DIR / "reports"),
    "exports_dir": str(DEFAULT_DATA_DIR / "exports"),
    "logs_dir": str(DEFAULT_DATA_DIR / "logs"),
    "editor": os.environ.get("EDITOR", "nano"),
    "default_severity": "medium",
    "default_platform": "hackerone",
    "report_author": "Security Researcher",
    "report_company": "",
    "date_format": "%Y-%m-%d",
    "datetime_format": "%Y-%m-%d %H:%M:%S",
    "confirm_destructive": True,
    # Tool paths — empty means use $PATH
    "tools": {
        "nmap": "",
        "subfinder": "",
        "amass": "",
        "httpx": "",
        "nuclei": "",
        "ffuf": "",
        "gobuster": "",
        "sqlmap": "",
        "nikto": "",
        "whatweb": "",
    },
    # HackerOne API credentials
    "hackerone": {
        "username": "",
        "api_token": "",
    },
    # Live scanner integration
    "scanner": {
        "zap": {
            "url": "http://localhost:8080",
            "api_key": "",
        },
        "burp": {
            "url": "http://localhost:1337",
            "api_key": "",
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning new dict."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config() -> dict:
    """Load config from disk, merged over defaults."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            user_cfg = yaml.safe_load(f) or {}
        return _deep_merge(DEFAULTS, user_cfg)
    return DEFAULTS.copy()


def save_config(cfg: dict):
    """Write config to disk."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)


def ensure_dirs(cfg: dict | None = None):
    """Create all configured directories if they don't exist."""
    cfg = cfg or load_config()
    for key in ("data_dir", "evidence_dir", "reports_dir", "exports_dir", "logs_dir"):
        Path(cfg[key]).mkdir(parents=True, exist_ok=True, mode=0o700)


def get_config_value(key: str, cfg: dict | None = None):
    """Get a dot-separated config key, e.g. 'tools.nmap'."""
    cfg = cfg or load_config()
    parts = key.split(".")
    val = cfg
    for part in parts:
        if isinstance(val, dict) and part in val:
            val = val[part]
        else:
            return None
    return val


def set_config_value(key: str, value, cfg: dict | None = None) -> dict:
    """Set a dot-separated config key, save, and return updated config."""
    cfg = cfg or load_config()
    parts = key.split(".")
    target = cfg
    for part in parts[:-1]:
        if part not in target or not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]
    target[parts[-1]] = value
    save_config(cfg)
    return cfg


# ── Active project context ──────────────────────────────────────

_ACTIVE_PROJECT_FILE = DEFAULT_DATA_DIR / ".active_project"


def get_active_project() -> int | None:
    """Return the active project ID, or None if not set."""
    if _ACTIVE_PROJECT_FILE.exists():
        text = _ACTIVE_PROJECT_FILE.read_text().strip()
        if text.isdigit():
            return int(text)
    return None


def set_active_project(project_id: int | None):
    """Set (or clear) the active project."""
    _ACTIVE_PROJECT_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if project_id is None:
        _ACTIVE_PROJECT_FILE.unlink(missing_ok=True)
    else:
        _ACTIVE_PROJECT_FILE.write_text(str(project_id))


def clear_active_project():
    """Clear the active project."""
    set_active_project(None)
