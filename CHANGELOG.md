# Changelog

All notable changes to BBRadar will be documented in this file.

## [0.3.1] — 2026-03-25

### Added

- **Scope change detection** — watch HackerOne programs and get alerted when
  their scope changes:
  - `bb h1 watch <handle>` — subscribe to a program's scope, takes initial snapshot
  - `bb h1 unwatch <handle>` — stop watching
  - `bb h1 watchlist` — show all watched programs with scope counts and timestamps
  - `bb h1 check` — check all watched programs for new, removed, or changed assets
  - `bb h1 check <handle>` — check a single program
  - `bb h1 check --new-programs` — discover recently launched H1 programs you're not tracking
  - `bb h1 check --auto-import` — automatically import new scope assets into linked projects
- **Notifications** — get alerts via Discord or desktop when scope changes:
  - `bb h1 notify discord <url>` — configure Discord webhook
  - `bb h1 notify desktop on/off` — toggle desktop notifications (notify-send)
  - `bb h1 notify test` — test all configured channels
  - `bb h1 notify status` — show channel configuration
  - `bb h1 monitor` — check all watched programs and send notifications (cron-friendly)
  - `bb h1 monitor --auto-import --new-programs -q` — full automation mode
  - Credentials via env var `BBRADAR_DISCORD_WEBHOOK` (recommended) or config
- Auto-links watched programs to BBRadar projects imported from the same H1 handle
- **Local program cache with filters** — instant, offline-capable program browsing:
  - `bb h1 programs --bounties` — show only bounty-paying programs
  - `bb h1 programs --search <term>` — filter by name or handle
  - `bb h1 programs --sort {name,newest,handle}` — sort results
  - `bb h1 programs --state <state>` — filter by program state
  - `bb h1 programs --refresh` — force re-fetch from API (auto-refreshes every 24h)
  - DB migration #3: `h1_program_cache` table with indexed columns
- DB migration #2: `h1_watched_programs`, `h1_scope_snapshots` tables, `h1_handle` project column

## [0.2.0] — 2026-03-25

### Added

- **HackerOne API integration** — new `bb h1` command with 10 subcommands:
  - `bb h1 auth` / `bb h1 status` — configure and check API credentials
  - `bb h1 programs` / `bb h1 search` — list and discover programs
  - `bb h1 import <handle>` — import a program as a project with targets and scope
  - `bb h1 scope-sync` — sync scope rules from HackerOne into an existing project
  - `bb h1 reports` / `bb h1 report <id>` — track submitted reports
  - `bb h1 balance` / `bb h1 earnings` — monitor earnings
  - `bb dashboard` — combined local + HackerOne overview
- **Active project context** (`bb use <id>`) — set a default project to avoid
  typing the project ID on every command. Applies to `target`, `recon`, and
  other project-scoped commands.
- **`--json` global flag** — output results as JSON for scripting and piping
  to `jq`. Works on `project list/show`, `target list`, `recon list`,
  `vuln list/show`, `status`, and more.
- **`--stdin` piping support** — bulk-add targets or recon data from stdin:
  - `cat domains.txt | bb target add --stdin --type domain`
  - `cat subs.txt | bb recon add <target_id> subdomain --stdin`
- **Shell tab completion** (`bb completion bash/zsh/fish`) — generate
  completion scripts for your shell.
- **`--no-color` flag and `NO_COLOR` env var** — disable ANSI color codes for
  piping, logging, and accessibility.
- **Environment variable credentials** — HackerOne API credentials can be set
  via `BBRADAR_H1_USERNAME` and `BBRADAR_H1_API_TOKEN` env vars instead of
  storing them in `config.yaml`.

### Security

- **Fixed command injection in recon.py** — `ingest_subfinder()`,
  `ingest_nmap()`, and `ingest_httpx()` previously built shell commands via
  f-string interpolation. Now uses subprocess argument lists (no shell).
- **Added input validation** — domain/target values are validated against a
  safe character regex before being passed to external tools.
- **`run_tool()` accepts argument lists** — the utility function now supports
  both list and string inputs, preferring lists to avoid shell injection.
- **httpx stdin piping** — replaced `echo '...' | httpx` shell pipe with
  `subprocess.run(input=...)` for safe data passing.

### Changed

- `run_tool()` in `core/utils.py` now accepts `list[str]` (preferred) or
  `str` (backward-compatible, split via `shlex`).
- `_get_credentials()` in `hackerone.py` checks env vars before config file.
- `severity_color()` respects the `NO_COLOR` environment variable.
- Quick-start tips in `bb --help` updated to show new features.

## [0.1.0] — 2026-03-20

### Added

- Initial release
- Project, target, vulnerability, note, and evidence management
- Scope rule engine with wildcard, CIDR, regex, and exact matching
- 15 tool output parsers (Nmap, Burp, Nuclei, ZAP, and more)
- Knowledge base integration (CWE, CAPEC, VRT, Nuclei templates)
- Workflow engine with pre-built assessment workflows
- Interactive wizards for common tasks
- Report generation (Markdown, HTML, PDF)
- Full audit logging
- Database backup, restore, and migration support
