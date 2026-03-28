<p align="center">
  <h1 align="center">BBRadar</h1>
  <p align="center">
    <strong>Local-first bug bounty hunting platform for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#features">Features</a> •
    <a href="#hackerone-integration">HackerOne</a> •
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
- **Knowledge-backed** — built-in CWE, CAPEC, VRT, Nuclei, CVE, KEV, and EPSS databases

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

# 3. Set it as your active project (skip typing the ID every time)
bb use 1

# 4. Add a vulnerability using the guided wizard
bb wizard vuln

# 5. Generate a report
bb report full --format markdown
```

### HackerOne workflow

```bash
# Import a program directly from HackerOne (creates project + targets + scope)
bb h1 auth
bb h1 import security
bb use 1
bb dashboard
```

### Manual workflow (without wizards)

```bash
bb project create "HackerOne - Acme Corp" --platform hackerone --url "https://hackerone.com/acme"
bb use 1
bb target add 1 acme.com --type domain
bb scope add 1 "*.acme.com"
bb recon run subfinder 1
bb vuln create "SQL Injection in /api/users" --severity critical
bb report full 1
```

### Piping & scripting

```bash
# Pipe targets from a file
cat domains.txt | bb target add --stdin --type domain

# JSON output for scripting
bb --json target list | jq '.[].value'
bb --json vuln list | jq '.[] | select(.severity == "critical")'

# Disable colors when piping
bb --no-color vuln list > findings.txt
# Or set the NO_COLOR env var globally
export NO_COLOR=1
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
bb ingest file scan.xml 1 --tool nmap

# Auto-detect the tool format
bb ingest file scan_output.json 1
```

### Knowledge Base
Seven integrated security databases, synced and searchable locally:

- **CWE** — MITRE Common Weakness Enumeration
- **CAPEC** — MITRE Common Attack Pattern Enumeration
- **VRT** — Bugcrowd Vulnerability Rating Taxonomy
- **Nuclei** — ProjectDiscovery Nuclei Templates
- **CVE** — NIST National Vulnerability Database (NVD API 2.0)
- **KEV** — CISA Known Exploited Vulnerabilities catalog
- **EPSS** — FIRST.org Exploit Prediction Scoring System

```bash
bb kb sync              # Download / update all databases
bb kb sync -s cve       # Sync only CVE data from NVD
bb kb search xss        # Search across all sources
bb kb cve CVE-2024-1234 # Full CVE detail: CVSS, KEV status, EPSS score
bb kb kev               # Browse recently added exploited vulnerabilities
bb kb kev --search log4j # Search KEV by vendor, product, or CVE
bb kb cwe 79            # Look up CWE details
bb kb enrich 42         # Enrich finding #42 with KB data + CVE intel
bb kb status            # Show sync status and record counts
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

### HackerOne Integration

Connect BBRadar to HackerOne for program discovery, scope import, report
tracking, and earnings monitoring:

```bash
bb h1 auth                          # Configure API credentials
bb h1 status                        # Check connection
bb h1 programs                      # List all programs (cached locally)
bb h1 programs --bounties           # Only bounty-paying programs
bb h1 programs --search "fintech"   # Filter by keyword
bb h1 programs --sort newest        # Sort by launch date
bb h1 programs --state public_mode  # Filter by state
bb h1 programs --refresh            # Force re-fetch from H1 API
bb h1 search "ecommerce"            # Discover programs (API search)
bb h1 import <handle>               # Import program → project + targets + scope
bb h1 scope-sync                    # Sync scope updates (uses active project)
bb h1 scope-sync <project_id> <handle>  # ...or specify explicitly
bb h1 reports                       # List your submitted reports
bb h1 balance                       # Current balance
bb h1 earnings                      # Earnings summary
bb h1 watch                         # Watch active project's H1 program for scope changes
bb h1 watch <handle>                # ...or specify a handle
bb h1 unwatch                       # Stop watching (active project)
bb h1 watchlist                     # List all watched programs
bb h1 check                         # Check all watched programs for changes
bb h1 check <handle>                # Check a specific program
bb h1 check --new-programs          # Find newly launched H1 programs
bb h1 check --auto-import           # Auto-import new scope into linked projects
bb h1 intel                         # Program intel (uses active project's H1 handle)
bb h1 intel <handle>                # ...or specify a handle
bb h1 intel <handle> --refresh      # Force re-fetch (12h cache)
bb h1 weaknesses                    # Accepted weakness/CWE types (active project)
bb h1 weaknesses <handle>           # ...or specify a handle
bb h1 notify discord <webhook_url>  # Configure Discord alerts (default for all)
bb h1 notify discord-scope <url>    # Scope changes → dedicated channel
bb h1 notify discord-programs <url> # New programs → dedicated channel
bb h1 notify discord-vulns <url>    # Vuln lifecycle → dedicated channel
bb h1 notify discord-ingest <url>   # Scan imports → dedicated channel
bb h1 notify verbosity <level>      # Set detail level (minimal/summary/verbose)
bb h1 notify desktop on             # Enable desktop notifications
bb h1 notify test                   # Test all configured channels
bb h1 notify status                 # Show notification channel status
bb h1 monitor                       # Check scope + new programs + hacktivity + notify
bb h1 monitor --auto-import         # Monitor + auto-import new scope
bb h1 monitor -q                    # Quiet mode — only output on changes
bb dashboard                        # Combined local + H1 dashboard
```

#### Notifications & Monitoring

Set up Discord alerts so you never miss a scope change or new program:

```bash
# 1. Set a single default webhook (all events use this as fallback)
bb h1 notify discord <webhook_url>

# Or configure separate channels per event type
bb h1 notify discord-scope <url>      # scope changes
bb h1 notify discord-vulns <url>      # critical/high findings, status changes, bounties
bb h1 notify discord-ingest <url>     # scan import summaries
bb h1 notify discord-programs <url>   # new H1 programs

# 2. Env vars work too (stays off git)
export BBRADAR_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export BBRADAR_DISCORD_SCOPE_WEBHOOK="https://discord.com/api/webhooks/..."
export BBRADAR_DISCORD_VULNS_WEBHOOK="https://discord.com/api/webhooks/..."
export BBRADAR_DISCORD_INGEST_WEBHOOK="https://discord.com/api/webhooks/..."

# 3. Control detail level (default: minimal — no PII, project IDs only)
bb h1 notify verbosity summary    # includes tool names and vuln types
bb h1 notify verbosity verbose    # also includes project names

# 4. Enable desktop popups too (requires libnotify / notify-send)
bb h1 notify desktop on

# 5. Test it
bb h1 notify test

# 6. Run manually or from cron
bb h1 monitor --auto-import

# Cron: check every 15 minutes
# */15 * * * * cd ~/bbradar && .venv/bin/bb h1 monitor --auto-import -q 2>/dev/null
```

Credentials can be set via environment variables (recommended) or config file:

```bash
export BBRADAR_H1_USERNAME="your_username"
export BBRADAR_H1_API_TOKEN="your_api_token"
```

### Active Project Context

Set an active project once, then every project-scoped command uses it
automatically — no more typing IDs:

```bash
bb use 3                # Set project 3 as active
bb use                  # Show current active project
bb target list          # Automatically uses project 3
bb target add example.com --type domain
bb scope list           # No project ID needed
bb scope add "*.acme.com"
bb ingest file scan.xml
bb report full
bb h1 intel             # Uses project's linked H1 handle
bb h1 watch             # Watch the linked H1 program
bb h1 scope-sync        # Sync scope from H1
bb use --clear          # Clear the active project
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
| `bb use` | Set/show active project (skip typing project IDs) |
| `bb project` | Manage projects (create, list, show, delete) |
| `bb target` | Manage targets (add, list, remove, import, `--stdin`) |
| `bb scope` | Manage scope rules (add, list, check, remove) |
| `bb recon` | Manage reconnaissance data (add, list, import, run, `--stdin`) |
| `bb vuln` | Track vulnerabilities (create, list, update, transitions, duplicates, merge, quick) |
| `bb note` | Manage assessment notes |
| `bb evidence` | Evidence files (stats, orphans, cleanup) |
| `bb report` | Generate reports (markdown, html, pdf, json) |
| `bb ingest` | Ingest tool output (15 supported tools) |
| `bb workflow` | Run assessment workflows (list, run, preflight) |
| `bb wizard` | Interactive wizards (project, target, vuln, quick) |
| `bb templates` | Browse / search vulnerability templates |
| `bb kb` | Knowledge base (sync, search, cve, kev, enrich, stats) |
| `bb h1` | HackerOne API (auth, programs, import, reports, earnings) |
| `bb dashboard` | Combined BBRadar + HackerOne dashboard |
| `bb config` | View / edit configuration |
| `bb audit` | Audit log (log, stats, purge, export) |
| `bb db` | Database management (backup, restore, migrate, status) |
| `bb completion` | Generate shell tab-completion (bash, zsh, fish) |

### Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (pipe to `jq`, scripts, etc.) |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR` env var) |

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
│   ├── config.py       # Configuration + active project context
│   ├── audit.py        # Audit logging
│   └── utils.py        # Shared utilities (tables, colors, shell helpers)
├── modules/
│   ├── projects.py     # Project CRUD
│   ├── targets.py      # Target management
│   ├── vulns.py        # Vulnerability tracking + state machine
│   ├── notes.py        # Notes
│   ├── scope.py        # Scope rule engine
│   ├── recon.py        # Recon data + tool integrations (subfinder, nmap, httpx)
│   ├── hackerone.py    # HackerOne API integration
│   ├── evidence.py     # Evidence file management
│   ├── reports.py      # Report generation (MD, HTML, PDF, JSON)
│   ├── ingest.py       # Tool output ingestion router
│   ├── workflows.py    # Workflow engine
│   ├── wizards.py      # Interactive wizards
│   ├── kb.py           # Knowledge base sync + search (CWE, CAPEC, VRT, Nuclei, CVE, KEV, EPSS)
│   └── parsers/        # 15 tool-specific output parsers
├── templates/           # Vulnerability templates (reserved)
└── workflows/           # Workflow definitions (YAML)
```

## Security

- All data stored locally in `~/.bbradar/` with restrictive permissions (0700)
- SQLite database with WAL mode for safe concurrent access
- No data leaves the machine — no cloud dependencies, no telemetry
- Full audit trail of every creation, update, deletion, and export
- Tool commands executed via subprocess argument lists (no shell injection)
- Target/domain input validation before passing to external tools
- All SQL queries use parameterized placeholders (no string concatenation)
- YAML parsed with `yaml.safe_load()` only
- HackerOne credentials support environment variables (avoid plaintext on disk)
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
