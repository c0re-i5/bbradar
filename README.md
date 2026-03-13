<p align="center">
  <h1 align="center">BBRadar</h1>
  <p align="center">
    <strong>Local-first bug bounty hunting platform for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#features">Features</a> •
    <a href="#supported-tools">Supported Tools</a> •
    <a href="#legal">Legal</a>
  </p>
</p>

---

> **⚠️ AUTHORIZED USE ONLY**
>
> BBRadar is designed **exclusively** for legal, authorized security testing —
> such as bug bounty programs, penetration tests with written permission, and
> security assessments on systems you own. **Unauthorized access to computer
> systems is illegal.** See [DISCLAIMER.md](DISCLAIMER.md) for the full legal
> notice. By using this software, you agree to use it responsibly and lawfully.

---

## What is BBRadar?

BBRadar is a single-user, local-first command-line platform that organizes your
entire bug bounty workflow — from reconnaissance through report submission. It
replaces scattered notes, spreadsheets, and terminal history with a structured
SQLite-backed workspace that tracks your projects, targets, scope, findings,
evidence, and reports in one place.

**Key design principles:**

- **Local-first** — all data stays on your machine in `~/.bbradar/`
- **Single-user** — designed for individual researchers, no server or accounts
- **CLI-native** — works entirely from the terminal via the `bb` command
- **Tool-agnostic** — ingest output from 15+ security tools automatically
- **Knowledge-backed** — built-in CWE, CAPEC, VRT, and Nuclei template databases

## Installation

### Requirements

- Python 3.10+
- Kali Linux (recommended) or any Linux distribution
- SQLite (bundled with Python)

### Install from source

```bash
git clone https://github.com/c0re-i5/bbradar.git
cd bbradar
pip install -e .
bb init
```

### Optional dependencies

```bash
# PDF report generation
pip install -e ".[pdf]"

# Development tools (pytest, black, ruff)
pip install -e ".[dev]"
```

### Verify installation

```bash
bb --help
```

## Quick Start

```bash
# 1. Initialize BBRadar (first-time setup — creates DB and syncs knowledge base)
bb init

# 2. Start a new project with the interactive wizard
bb wizard project

# 3. Add a vulnerability using the guided wizard
bb wizard vuln

# 4. Or use the quick one-liner for fast entry
bb vuln quick --project 1 --title "Reflected XSS in search" --severity high

# 5. Generate a report
bb report generate --project 1 --format markdown
```

### Manual workflow (without wizards)

```bash
bb project create "HackerOne - Acme Corp" --platform hackerone --url "https://hackerone.com/acme"
bb target add --project 1 --type domain --value "acme.com"
bb scope add --project 1 --type include --pattern "*.acme.com"
bb recon run --project 1 --tool subfinder
bb vuln create --project 1 --title "SQL Injection in /api/users" --severity critical
bb report generate --project 1
```

## Features

### Project & Target Management
- Create and manage multiple bug bounty engagements
- Track targets by type: domains, IPs, URLs, CIDR ranges
- Define include/exclude scope rules with wildcard patterns
- Automatic scope validation when adding targets
- Bulk import targets from files

### Vulnerability Tracking
- Full lifecycle tracking: `new` → `confirmed` → `reported` → `accepted` / `rejected` / `duplicate`
- 30 built-in vulnerability templates (XSS, SQLi, SSRF, IDOR, and more)
- Severity classification: critical, high, medium, low, info
- Cross-project duplicate detection and merge capability
- Evidence file attachment with size validation

### Tool Ingestion

Automatically parse output from security tools and create structured findings:

| Tool | Format |
|------|--------|
| Nmap | XML |
| Burp Suite | XML |
| Nuclei | JSON / JSONL |
| ZAP | XML |
| Nikto | JSON |
| SQLMap | Log |
| FFUF | JSON |
| WPScan | JSON |
| Semgrep | JSON |
| TestSSL | JSON |
| Metasploit | XML |
| Acunetix | XML |
| Qualys | XML |
| Fortify | XML (FPR) |
| Veracode | XML |

```bash
# Ingest a single scan
bb ingest --project 1 --tool nmap --file scan.xml

# Auto-detect the tool format
bb ingest --project 1 --file scan_output.json
```

### Knowledge Base
Four integrated security databases, synced and searchable locally:

- **CWE** — MITRE Common Weakness Enumeration
- **CAPEC** — MITRE Common Attack Pattern Enumeration
- **VRT** — Bugcrowd Vulnerability Rating Taxonomy
- **Nuclei** — ProjectDiscovery Nuclei Templates

```bash
bb kb sync          # Download / update all databases
bb kb search xss    # Search across all sources
bb kb stats         # Show database statistics
```

### Workflows
Pre-built assessment workflows that guide you through multi-step processes:

- **recon-basic** — Subdomain enumeration → live host detection → port scanning
- **recon-deep** — Full reconnaissance including tech detection, certificate transparency, Wayback Machine, JS/parameter discovery
- **vuln-scan** — Automated scanning with Nuclei, Nikto, security headers, SSL/TLS analysis

```bash
bb workflow list
bb workflow run recon-basic --project 1
bb workflow preflight recon-basic    # Check tool availability before running
```

### Interactive Wizards
Guided step-by-step wizards for common tasks:

```bash
bb wizard project   # Create project with scope + targets
bb wizard target    # Add targets with scope validation
bb wizard vuln      # Report vulnerability from templates with dedup check
bb wizard quick     # Rapid finding entry
```

### Reports
Generate structured reports in multiple formats:

```bash
bb report generate --project 1 --format markdown
bb report generate --project 1 --format html
bb report generate --project 1 --format pdf       # Requires weasyprint
bb report generate --project 1 --format json
```

### Evidence Management
```bash
bb evidence stats           # File counts, sizes, referenced vs orphaned
bb evidence orphans         # List orphaned evidence files
bb evidence cleanup         # Dry run — show what would be deleted
bb evidence cleanup --execute   # Actually remove orphaned files
```

### Audit Log
Every action is logged for accountability:

```bash
bb audit log                # View recent audit entries
bb audit stats              # Summary statistics
bb audit purge --days 90    # Clean up old entries
bb audit export             # Export full log
```

### Database Management
```bash
bb db backup                # Create timestamped backup
bb db restore <file>        # Restore from backup
bb db migrate               # Apply pending schema migrations
bb db status                # Show DB version and migration state
```

## Command Reference

| Command | Description |
|---------|-------------|
| `bb init` | Initialize BBRadar (first-time setup) |
| `bb status` | Show workspace status |
| `bb project` | Manage projects (create, list, show, delete) |
| `bb target` | Manage targets (add, list, remove) |
| `bb scope` | Manage scope rules (add, list, check, remove) |
| `bb recon` | Manage reconnaissance data |
| `bb vuln` | Track vulnerabilities (create, list, update, transitions, duplicates, merge, quick) |
| `bb note` | Manage assessment notes |
| `bb evidence` | Evidence files (stats, orphans, cleanup) |
| `bb report` | Generate reports (markdown, html, pdf, json) |
| `bb ingest` | Ingest tool output (15 supported tools) |
| `bb workflow` | Run assessment workflows (list, run, preflight) |
| `bb wizard` | Interactive wizards (project, target, vuln, quick) |
| `bb templates` | Browse / search vulnerability templates |
| `bb kb` | Knowledge base (sync, search, stats) |
| `bb config` | View / edit configuration |
| `bb audit` | Audit log (log, stats, purge, export) |
| `bb db` | Database management (backup, restore, migrate, status) |

Run `bb <command> --help` for detailed usage of any command.

## Architecture

```
~/.bbradar/
├── bbradar.db          # SQLite database (WAL mode)
├── evidence/           # Attached evidence files
├── backups/            # Database backups
└── config.yaml         # User configuration

bbradar/
├── cli.py              # CLI entry point and command routing
├── core/
│   ├── database.py     # SQLite connection management and migrations
│   └── audit.py        # Audit logging
├── modules/
│   ├── projects.py     # Project CRUD
│   ├── targets.py      # Target management
│   ├── vulns.py        # Vulnerability tracking + state machine
│   ├── notes.py        # Notes
│   ├── scope.py        # Scope rule engine
│   ├── evidence.py     # Evidence file management
│   ├── reports.py      # Report generation (MD, HTML, PDF, JSON)
│   ├── ingest.py       # Tool output ingestion router
│   ├── workflows.py    # Workflow engine
│   ├── wizards.py      # Interactive wizards
│   ├── kb.py           # Knowledge base sync + search
│   └── parsers/        # 15 tool-specific output parsers
├── templates/           # Vulnerability templates (reserved)
└── workflows/           # Workflow definitions (YAML)
```

## Security

- All data stored locally in `~/.bbradar/` with restrictive permissions
- SQLite database with WAL mode for safe concurrent access
- No data leaves the machine — no cloud dependencies, no telemetry
- Full audit trail of every creation, update, deletion, and export
- Tool commands executed through safe argument handling
- Concurrent access protection with SQLite busy timeout

## Legal

### License

BBRadar is released under the [MIT License](LICENSE).

### Authorized Use Only

This software is provided for **legal, authorized security testing only**.

You **MUST** have explicit written permission to test any system that you do not
own. Unauthorized access to computer systems is a criminal offense in most
jurisdictions.

The authors and contributors:
- Accept **no responsibility** for misuse of this software
- Provide **no warranty** of any kind
- Do **not** provide legal advice

See [DISCLAIMER.md](DISCLAIMER.md) for the complete legal and ethical use
policy.

### Responsible Disclosure

If you find vulnerabilities using BBRadar, please follow responsible disclosure
practices:

1. Report findings to the affected organization through their official channels
2. Allow reasonable time for remediation before any public disclosure
3. Do not access, modify, or exfiltrate data beyond what is necessary to
   demonstrate the vulnerability
4. Respect bug bounty program rules and scope boundaries

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

---

<p align="center">
  <sub>Built for security researchers. Use responsibly.</sub>
</p>
