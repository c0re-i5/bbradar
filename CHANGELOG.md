# Changelog

All notable changes to BBRadar will be documented in this file.

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
