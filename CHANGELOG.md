# Changelog

All notable changes to BBRadar will be documented in this file.

## [0.6.0] — 2026-04-05

### Added

- **Web page analyzer** (`bb analyze page <url>`) — passive page analysis:
  technology fingerprinting (30+ signatures), security header audit (10 headers),
  form/input discovery, JS file extraction, link/endpoint enumeration, HTML
  comment extraction, cookie attribute analysis, meta tag leak detection.
  Results stored as recon_data for target integration.
- **JavaScript analysis pipeline** (`bb js analyze <target_id>`) — discovers
  JS files from recon data, fetches and scans for: hardcoded secrets (AWS keys,
  GitHub tokens, Slack webhooks, Firebase URLs, JWTs, private keys, generic API
  keys), API endpoints, internal IPs, S3/GCS/Azure cloud URLs, source maps.
  Also `bb js scan <url>` for single-file analysis.
- **Parameter classification** (`bb params classify <target_id>`) — heuristic
  classification of discovered parameters into vulnerability classes: IDOR, SSRF,
  SQLi, XSS, LFI, open redirect, RCE, info leak. Confidence scoring (high/medium).
  `bb params suggest` generates actionable test suggestions per parameter.
- **Attack surface diffing** (`bb diff`) — snapshot recon state, compare snapshots,
  detect changes. `bb diff snapshot` captures current state, `bb diff compare`
  shows added/removed entries by data type, `bb diff current` auto-diffs against
  last snapshot with optional Discord/desktop notifications.
- **Parallel workflow execution** — workflow steps marked `parallel: true` now
  run concurrently via ThreadPoolExecutor. Adjacent parallel steps are batched
  automatically. Concurrency controlled by `max_parallel` workflow config
  (default: 4).
- **VRT enrichment in enrich_vuln()** — vulnerability enrichment now queries
  the VRT knowledge base for priority classification alongside existing CWE,
  CAPEC, nuclei, CVE, KEV, and EPSS data.
- **34 new tests** covering all new modules (jsanalyzer, param_classifier,
  analyzer, differ) — secret detection, endpoint extraction, parameter
  classification, snapshot/diff operations, report formatting.

### Fixed

- **notify_ingest_complete()** — the function was called from `ingest.py` but
  never defined in `notifier.py` (silently failing via ImportError catch). Now
  properly implemented with Discord webhook and desktop notification support.

### Infrastructure

- Database migration #6: `recon_snapshots` table for attack surface diffing
- 4 new CLI commands: `diff`, `analyze`, `js`, `params` (28 total commands)
- 4 new modules: `analyzer.py`, `jsanalyzer.py`, `param_classifier.py`, `differ.py`

## [0.5.6] — 2026-04-05

### Fixed

- **[HIGH] TOCTOU race conditions in vulns.py** — `update_vuln` status
  transition check, `add_evidence` read-modify-write, and `merge_vulns`
  reads+writes all moved into a single `get_connection()` block to prevent
  concurrent modification races
- **[HIGH] Falsy-zero ID checks** — 14 sites across 6 modules changed
  `if project_id:` → `if project_id is not None:` so ID 0 is handled
  correctly (`vulns.py`, `notes.py`, `projects.py`, `recon.py`,
  `reports.py`, `workflows.py`)
- **[MEDIUM] Silent parser failures** — 12 parsers now log a warning via
  `logging.warning()` instead of silently returning `[]` on parse errors
  (`nmap`, `burp`, `acunetix`, `fortify`, `veracode`, `qualys`, `ffuf`,
  `semgrep`, `testssl`, `wpscan`, `metasploit`, `masscan`)
- **[MEDIUM] Swallowed exceptions** — `database.py` migration failures,
  `hackerone.py` `import_program` / `sync_scope` target and rule errors
  now log warnings instead of silently passing
- **[MEDIUM] ReDoS protection in scope.py** — `_validate_pattern()` now
  strips escape sequences before detecting nested quantifiers, and rejects
  regex patterns longer than 1024 characters
- **[MEDIUM] Stale active project after delete** — deleting the active
  project now clears the active project reference; console prompt
  auto-clears if the project no longer exists (`cli.py`, `console.py`)
- **[LOW] delete_* silent failures** — `delete_vuln`, `delete_target`,
  `delete_note`, `delete_recon`, `delete_rule` now check `cursor.rowcount`
  and return `False` for non-existent IDs
- **[LOW] Inline `import sys`** — moved to top-level imports in 6 modules
  (`targets.py`, `recon.py`, `vulns.py`, `workflows.py`, `hackerone.py`,
  `wizards.py`)

### Changed

- **Console prompt restyled** — new compact `bb:ProjectName#id ❯` format
  (msfconsole-inspired) replaces the old `bb (ProjectName) >` style
- **N+1 queries in `get_project_stats`** — consolidated 4 separate COUNT
  queries into a single query with scalar subqueries (`projects.py`)
- **Fragile query building in `list_recon`** — replaced `"rd." not in query`
  substring detection with a `col` prefix variable (`recon.py`)

## [0.5.5] — 2026-03-31

### Fixed

- **[HIGH] XSS in HTML reports** — `_md_to_html()` sanitizer expanded from
  only stripping `<script>` to also removing `<iframe>`, `<object>`,
  `<embed>`, `<applet>`, `<form>`, `<base>`, `<link>` tags plus `on*=`
  event handlers and `javascript:`/`data:`/`vbscript:` URIs (`reports.py`)
- **[HIGH] Path traversal in workflow loader** — `load_workflow()` now
  validates resolved paths stay inside `WORKFLOW_DIR`, blocking absolute
  path or `../` escapes (`workflows.py`)
- **[HIGH] ZAP parser data loss** — `_parse_alert()` returned a single dict
  instead of a list, silently dropping all but the first instance per alert;
  now returns all instances (`parsers/zap.py`)
- **[HIGH] Fortify parser missing CWE** — `cwe_id` was always empty;
  now extracts from `CweId` and `ClassID` elements. Also fixed XPath
  `@path` attribute access (`parsers/fortify.py`)
- **[HIGH] Console readline crash** — `readline.__doc__` can be `None`;
  added guard before `"libedit" in` check (`console.py`)
- **[HIGH] Semgrep auto-detection** — was calling `.get()` on a list
  instead of `list[0].get()`; also tightened Burp XML detection and
  removed `<?xml` from signature boosts (`parsers/__init__.py`)
- **[MEDIUM] Vuln state machine bypass** — `merge_vulns` set status to
  `"duplicate"` without checking transitions; added `"duplicate"` to
  accepted→ transitions (`vulns.py`)
- **[MEDIUM] Notifier dead-code status** — `notable_states` contained
  `"rejected"` which is not a valid status; changed to `"wontfix"`
  (`notifier.py`)
- **[MEDIUM] Recon bulk-add overcounting** — `bulk_add_recon` incremented
  count even when `INSERT OR IGNORE` was a no-op; now checks `rowcount`
  (`recon.py`)
- **[MEDIUM] Recon bare exception** — `add_recon` caught `Exception`
  instead of `sqlite3.IntegrityError` for duplicate handling (`recon.py`)
- **[MEDIUM] Scope partial-update validation** — `update_rule` now fetches
  the missing field from DB to validate the pattern/type pair on partial
  updates (`scope.py`)
- **[MEDIUM] `--bounties-only` default** — flag defaulted to `True`,
  filtering results by default; changed to `False` (`cli.py`)
- **[MEDIUM] KEV connection leak** — total-count query reused a closed
  connection; now opens a separate `with` block (`cli.py`)
- **[MEDIUM] LIKE wildcard injection** — notes search/tag queries now
  escape `%` and `_` characters (`notes.py`)
- **[MEDIUM] SQL table-name injection** — `_intel_cache_fresh` now
  validates table names against an allowlist before interpolation
  (`hackerone.py`)
- **[MEDIUM] Burp XML false positives** — tightened detection to require
  `burpVersion` attribute specifically (`parsers/__init__.py`)
- **[MEDIUM] WPScan hardcoded severity** — `_parse_vuln` now derives
  severity from vuln-type keywords instead of always returning `"high"`
  (`parsers/wpscan.py`)
- **[LOW] `delete_project` silent failure** — now checks `cursor.rowcount`
  and returns `False` for non-existent project IDs (`projects.py`)
- **[LOW] Unused variable** — removed dead `base` assignment in
  `get_vuln_stats` (`vulns.py`)
- **[LOW] Cross-platform `cls`** — console `do_cls` now uses `cls` on
  Windows and `clear` elsewhere (`console.py`)

## [0.5.4] — 2026-03-31

### Added

- **Interactive console** — msfconsole-style REPL with tab completion,
  persistent readline history, dynamic prompt showing active project,
  command aliases/shortcuts, and colorized banner with live stats.
  Launch via `bb console` or the `bbradar-console` entry point.

- **Probe system** — `bb probe <target_id>` analyzes discovered recon data
  (open ports, services, technologies) and suggests or auto-runs follow-up
  tools. Supports `--auto`, `--dry-run`, `--port`, and `--service` filters.

- **5 new parsers** — Masscan, Gobuster, WhatWeb, Amass, and Dig output
  can now be ingested via `bb ingest`. Includes content-based auto-detection.

- **10 new tool runners** — `bb recon run` now supports 13 tools total:
  subfinder, nmap, httpx, masscan, nikto, nuclei, gobuster, ffuf, whatweb,
  testssl, wpscan, amass, and dig. Added `bb recon tools` to list them.

- **3 new workflow definitions** — `web-audit.yaml` (whatweb → gobuster →
  ffuf → nuclei → nikto → testssl), `full-recon.yaml` (subfinder → amass →
  dig → masscan → nmap → httpx → whatweb → gobuster), and
  `wordpress-audit.yaml` (whatweb → wpscan → nuclei → gobuster → nikto).

- **`bbradar-console` entry point** — typing `bbradar-console` launches the
  interactive console directly.

## [0.5.3] — 2026-03-30

### Fixed

- **[CRITICAL] Workflow command injection** — `run_workflow()` now builds
  commands as argument lists instead of string substitution, preventing
  shell metacharacter injection via target values (`workflows.py`)
- **[CRITICAL] XXE in XML parsers** — all 8 XML-based parsers (nmap, burp,
  acunetix, qualys, fortify, metasploit, zap, veracode) now use
  `defusedxml.ElementTree` to block XML External Entity attacks
- **[CRITICAL] Webhook domain spoofing** — `validate_webhook_url()` now
  requires exact `discord.com` or `*.discord.com` hostname, rejecting
  lookalike domains like `evil-discord.com` (`notifier.py`)
- **[HIGH] Version mismatch** — `__init__.py` version now matches
  `pyproject.toml` (was `0.5.0`, now `0.5.3`)
- **[HIGH] Recon extra_args sanitization** — `ingest_nmap()`,
  `ingest_subfinder()`, and `ingest_httpx()` now validate `extra_args`
  against an allowlist of safe option characters (`recon.py`)
- **[HIGH] ReDoS protection in scope regex** — improved nested-quantifier
  detection and added 2-second `re.search` timeout via `re.fullmatch` guard
  to prevent catastrophic backtracking (`scope.py`)
- **[HIGH] Migration failure safety** — `get_connection()` migration loop
  now catches `executescript` failures and does not bump `user_version`
  on partial failure (`database.py`)
- **[MEDIUM] Config `_deep_merge` mutation** — switched from shallow
  `dict.copy()` to `copy.deepcopy()` to prevent callers from mutating
  the global `DEFAULTS` dict (`config.py`)
- **[MEDIUM] Evidence orphan safe-path check** — `find_orphaned_files()`
  now calls `_is_safe_path()` to skip symlinks escaping the evidence
  directory (`evidence.py`)
- **[MEDIUM] `add_evidence` accepts missing files** — now raises
  `FileNotFoundError` instead of silently adding non-existent paths
  (`vulns.py`)
- **[MEDIUM] Ingest skipped-count arithmetic** — `total_parsed` is now
  captured before severity filtering so the skipped count is always
  non-negative (`ingest.py`)
- **[MEDIUM] IPv6 CIDR match mis-parse** — `_cidr_match()` now correctly
  handles bare IPv6 addresses by only stripping port suffixes from non-IPv6
  strings (`scope.py`)
- **[LOW] `normalize_cwe` silent failure** — returns `None` on unparseable
  input instead of echoing the invalid string (`utils.py`)
- **[LOW] URL validation accepts bare paths** — `validate_url()` now
  requires `http` or `https` scheme (`utils.py`)
- **[LOW] `get_audit_stats` None timestamp** — returns `"(none)"` instead
  of `None` when audit log is empty (`audit.py`)
- **[LOW] Recon `_SAFE_TARGET_RE` too permissive** — tightened regex to
  reject path-traversal sequences (`recon.py`)
- **[LOW] HTML report XSS** — `_md_to_html()` now sanitizes the markdown
  body by stripping `<script>` tags before rendering (`reports.py`)

### Added

- `defusedxml` added as a required dependency in `pyproject.toml`

## [0.5.2] — 2026-03-28

### Added

- **Vuln lifecycle notifications** — Discord alerts when critical/high findings
  are created or when findings change to notable states (accepted, rejected,
  duplicate, bounty awarded):
  - `notify_vuln_created()` — fires on critical/high severity only
  - `notify_vuln_status_change()` — fires on accepted, rejected, duplicate, or
    bounty award, includes bounty amount when applicable
  - Wired into `create_vuln()` and `update_vuln()` with fail-safe guards
  - Dedicated channel: `bb h1 notify discord-vulns <url>` or env var
    `BBRADAR_DISCORD_VULNS_WEBHOOK`

- **Ingest notifications** — Discord summary when scan imports produce new
  findings, with severity breakdown (e.g. 🔴 2 critical — 🟠 1 high):
  - `notify_ingest_complete()` — fires when new findings > 0, skips dry runs
  - Wired into `ingest_data()` with fail-safe guard
  - Dedicated channel: `bb h1 notify discord-ingest <url>` or env var
    `BBRADAR_DISCORD_INGEST_WEBHOOK`

- **Notification verbosity control** — three levels to control how much detail
  appears in outbound messages:
  - `minimal` (default) — project IDs only, no names, no tool names
  - `summary` — includes tool name and vuln type
  - `verbose` — includes project name alongside ID
  - Configure via `bb h1 notify verbosity <level>` or env var
    `BBRADAR_NOTIFY_VERBOSITY`

- **Non-PII project labels** — notifications use `Project #<id>` instead of
  program names by default, so Discord messages can't be linked to specific
  targets or programs.

- 26 new tests covering verbosity, project labels, vuln notifications, ingest
  notifications, and status display (363 total)

### Changed

- `bb h1 notify` choices expanded: `discord-vulns`, `discord-ingest`,
  `verbosity` alongside existing channel types
- `bb h1 notify status` now displays all 5 Discord channels + verbosity level
- `bb h1 notify test` now tests vulns and ingest channels
- `get_status()` returns `discord_vulns`, `discord_ingest`, and `verbosity`

## [0.5.1] — 2026-03-28

### Added

- **NVD CVE database** — sync and search the NIST National Vulnerability Database:
  - `bb kb sync --source cve` — incremental sync via NVD REST API 2.0
    (fetches only modified CVEs after initial load; 120-day window on first sync)
  - `bb kb cve CVE-2024-1234` — full CVE detail view: description, CVSS v3.1
    score/vector/severity, CWE mappings, affected CPE products, references,
    published/modified dates, KEV exploit status, and EPSS probability
  - Parsed fields: CVSS v3.1 (with v3.0 fallback), CWE IDs (excluding
    CWE-noinfo), affected CPE products, reference URLs with tags
  - NVD rate-limit aware (6s delay between paginated requests)
  - DB table: `kb_cve` with indexes on published date and severity

- **CISA KEV catalog** — track actively exploited vulnerabilities:
  - `bb kb sync --source kev` — download the CISA Known Exploited
    Vulnerabilities catalog with conditional HTTP and content hash dedup
  - `bb kb kev` — browse recent KEV entries sorted by date added
  - `bb kb kev --search "apache"` — search by vendor, product, or CVE ID
  - Tracks newly added KEV entries between syncs for notification dispatch
  - Ransomware campaign usage flagged in output
  - DB table: `kb_kev`

- **EPSS scores** — exploitation probability from FIRST.org:
  - `bb kb sync --source epss` — fetch EPSS scores for CVEs in the local
    database (batched, 100 per request per API limits)
  - Auto-refreshes stale scores (>7 days old) during sync
  - Supports targeted fetch for specific CVE lists
  - DB table: `kb_epss`

- **CVE lookup with combined intelligence** — `lookup_cve()` returns CVE
  details enriched with KEV exploit status and EPSS probability in a single
  call. Falls back to KEV-only lookup for zero-days not yet in NVD.

- **Enhanced vulnerability enrichment** — `enrich_vuln()` now extracts CVE
  IDs from descriptions and explicit fields, surfaces `actively_exploited`
  flag and `max_epss_score` alongside existing CWE/CAPEC/Nuclei enrichment.

- **Cross-source KB search** — `bb kb search` now includes CVE and KEV
  results alongside CWE, CAPEC, VRT, and Nuclei matches.

- **KEV notifications** — Discord embed + desktop alerts when new entries
  appear in the CISA KEV catalog during sync:
  - `notify_new_kev()` with red severity embed and ransomware flag
  - Works with existing Discord webhook configuration

- **Active project auto-resolution** — all project-scoped commands now
  auto-resolve the project ID from `bb use` context. No need to pass
  `project_id` explicitly for:
  - `bb scope add/exclude/list/clear/check/check-file/import/validate/overview`
  - `bb ingest file/dir/pipe/summary`
  - `bb report full/executive`
  - `bb vuln quick`
  - `bb h1 scope-sync/watch/unwatch/intel/weaknesses` (auto-resolves both
    project ID and H1 handle from the active project's `h1_handle` column)

- **H1 scope import in project wizard** — `bb wizard project` now offers to
  import scope from HackerOne when the platform is set to "hackerone" and
  H1 credentials are configured.

- **Wizard active project default** — `bb wizard target` and `bb wizard vuln`
  now offer the active project as a Y/n default instead of always listing
  all projects.

- DB migration #5: `kb_cve`, `kb_kev`, `kb_epss` tables with indexes
- 42 new tests covering sync parsing, lookup, search, enrichment,
  notifications, DB schema, and migration (337 total)

### Changed

- `bb kb` help text and parser updated to reflect all 7 sources
  (CWE, CAPEC, VRT, Nuclei, CVE, KEV, EPSS)
- `bb kb sync` choices expanded: `--source cve|kev|epss` alongside existing
  `cwe|capec|vrt|nuclei|all`
- `kb_stats()` now reports counts for all 7 KB tables
- `search_kb()` returns `cve` and `kev` result categories
- User-Agent updated to `BBRadar/0.5.1` across all HTTP clients

### Fixed

- **`offers_bounties` false negative** — `bb h1 intel` now checks scope asset
  `eligible_for_bounty` as a fallback when the H1 API returns
  `offers_bounties: false/null` for programs that do pay bounties.
- **KEV sync 404** — fixed CISA KEV catalog URL (underscores, not hyphens).
- **Stale watchlist after project delete** — `delete_project()` now removes
  linked H1 watch entries so `bb h1 check` no longer checks programs for
  deleted projects.

## [0.4.0] — 2026-03-26

### Added

- **Program intel** — gather disclosed reports, vulnerability types, and bounty
  statistics for any HackerOne program:
  - `bb h1 intel <handle>` — full program intel: severity breakdown, bounty
    stats (min/max/avg/total), top CWEs, top reporters, recent disclosures,
    and accepted weakness types
  - `bb h1 intel <handle> --refresh` — force re-fetch from API (12h cache)
  - `bb h1 weaknesses <handle>` — list all accepted weakness/CWE types
  - `bb h1 monitor` now also checks for newly disclosed hacktivity on watched
    programs and sends Discord alerts for new disclosures
  - DB migration #4: `h1_hacktivity_cache` and `h1_weakness_cache` tables

### Fixed

- Fixed `test_all_configured` notifier test leaking real config via `load_config()`

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
- **Notifications** — get alerts via Discord or desktop when scope changes or
  new programs appear:
  - `bb h1 notify discord <url>` — configure default Discord webhook
  - `bb h1 notify discord-scope <url>` — scope changes to a dedicated channel
  - `bb h1 notify discord-programs <url>` — new programs to a dedicated channel
  - `bb h1 notify desktop on/off` — toggle desktop notifications (notify-send)
  - `bb h1 notify test` — test all configured channels
  - `bb h1 notify status` — show channel configuration
  - `bb h1 monitor` — check watched programs + scan for new programs + notify
  - `bb h1 monitor --auto-import -q` — full automation mode for cron
  - Per-channel env vars: `BBRADAR_DISCORD_SCOPE_WEBHOOK`,
    `BBRADAR_DISCORD_PROGRAMS_WEBHOOK`, `BBRADAR_DISCORD_WEBHOOK` (fallback)
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
