"""
BBRadar Interactive Console — msfconsole-style REPL.

Provides a persistent interactive session with:
- Built-in tab completion for all commands, subcommands, tool names
- Command history (persisted across sessions)
- Dynamic prompt showing active project context
- Aliases and shortcuts
- Colorized output
"""

import cmd
import os
import readline
import shlex
import sys
from pathlib import Path

from . import __version__
from .cli import build_parser, COMMAND_MAP
from .core.config import (
    get_active_project, set_active_project, clear_active_project, load_config,
)
from .core.utils import set_no_color


# ═══════════════════════════════════════════════════════════════════
# Command → subcommand map for tab completion
# ═══════════════════════════════════════════════════════════════════

_SUBCOMMANDS = {
    "project":   ["create", "list", "show", "update", "delete", "stats"],
    "target":    ["add", "list", "import", "update", "delete"],
    "recon":     ["add", "list", "import", "summary", "export", "run", "tools"],
    "vuln":      ["create", "list", "show", "update", "delete", "evidence",
                  "stats", "quick", "transitions", "duplicates", "merge"],
    "note":      ["add", "list", "show", "edit", "delete", "export"],
    "report":    ["vuln", "full", "executive", "list"],
    "wizard":    ["project", "target", "vuln"],
    "templates": ["list", "show", "search", "categories"],
    "scope":     ["add", "exclude", "list", "delete", "clear", "check",
                  "check-file", "import", "validate", "overview", "wizard"],
    "ingest":    ["file", "dir", "pipe", "tools", "summary"],
    "kb":        ["sync", "status", "search", "cwe", "capec", "vrt",
                  "nuclei", "cve", "kev", "enrich"],
    "workflow":  ["list", "run", "show", "history", "preflight"],
    "probe":     [],  # no subcommands, just flags
    "evidence":  ["stats", "orphans", "cleanup"],
    "audit":     ["log", "stats", "purge", "export"],
    "config":    ["show", "set", "get"],
    "db":        ["backup", "restore", "migrate", "status"],
    "h1":        ["auth", "status", "programs", "search", "import",
                  "scope-sync", "reports", "report", "balance", "earnings",
                  "watch", "unwatch", "watchlist", "check", "notify",
                  "monitor", "intel", "weaknesses"],
    "completion": [],
    "dashboard": [],
    "init":      [],
    "status":    [],
    "use":       [],
}

# Tool names for `recon run <tool>` completion
_RECON_TOOLS = [
    "subfinder", "nmap", "httpx", "masscan", "nikto", "nuclei",
    "gobuster", "ffuf", "whatweb", "testssl", "wpscan", "amass", "dig",
]

# Workflow names for `workflow run <name>` completion
_WORKFLOW_NAMES = [
    "recon-basic", "recon-deep", "full-recon", "vuln-scan",
    "web-audit", "wordpress-audit",
]

# Aliases / shortcuts
_ALIASES = {
    "projects": "project list",
    "targets": "target list",
    "vulns": "vuln list",
    "findings": "vuln list",
    "notes": "note list",
    "scopes": "scope list",
    "tools": "recon tools",
    "scan": "recon run",
    "import": "ingest file",
    "help": "?",
    "exit": "quit",
    "q": "quit",
    "back": "use --clear",
    "clear": "cls",
}


# ═══════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════

def _banner(project_count: int = 0, vuln_count: int = 0,
            critical_count: int = 0) -> str:
    """Generate the startup banner."""
    # Build the stats line and pad to exactly 48 visible chars (50 inner - 2 leading spaces)
    stats = f"{project_count} projects | {vuln_count} findings | {critical_count} critical"
    stats_padded = f"{stats:<48}"
    return (
        f"\033[1;34m\n"
        f"    ╔══════════════════════════════════════════════════╗\n"
        f"    ║\033[1;37m{'BBRadar v' + __version__:^50s}\033[1;34m║\n"
        f"    ║\033[0;36m{'Bug Bounty Hunting Platform':^50s}\033[1;34m║\n"
        f"    ╠══════════════════════════════════════════════════╣\n"
        f"    ║  \033[0m{stats_padded}\033[1;34m║\n"
        f"    ╚══════════════════════════════════════════════════╝\033[0m\n"
        f"\n"
        f"    Type \033[1mhelp\033[0m for commands, \033[1mtab\033[0m to complete, \033[1mexit\033[0m to quit.\n"
    )


def _get_stats() -> tuple[int, int, int]:
    """Get quick stats for the banner."""
    try:
        from .modules import projects, vulns
        projs = projects.list_projects()
        stats = vulns.get_vuln_stats()
        return (
            len(projs),
            stats.get("total", 0),
            stats.get("by_severity", {}).get("critical", 0),
        )
    except Exception:
        return 0, 0, 0


# ═══════════════════════════════════════════════════════════════════
# Console REPL
# ═══════════════════════════════════════════════════════════════════

class BBConsole(cmd.Cmd):
    """Interactive BBRadar console."""

    intro = ""  # set dynamically in preloop
    doc_header = "Core Commands"
    misc_header = "Shortcuts"
    ruler = "─"

    def __init__(self):
        super().__init__()
        self._parser = build_parser()
        self._update_prompt()
        self._history_file = Path("~/.bbradar/.console_history").expanduser()

    # ── Prompt ────────────────────────────────────────────────────

    def _update_prompt(self):
        """Update prompt based on active project."""
        pid = get_active_project()
        if pid:
            try:
                from .modules import projects
                p = projects.get_project(pid)
                name = p["name"] if p else f"#{pid}"
                # Truncate long names
                if len(name) > 25:
                    name = name[:22] + "..."
                self.prompt = f"\033[1;31mbb\033[0m (\033[1;33m{name}\033[0m) > "
            except Exception:
                self.prompt = f"\033[1;31mbb\033[0m (#{pid}) > "
        else:
            self.prompt = "\033[1;31mbb\033[0m > "

    # ── Lifecycle ─────────────────────────────────────────────────

    def preloop(self):
        """Set up history and show banner."""
        # Load history
        self._history_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            if self._history_file.exists():
                readline.read_history_file(str(self._history_file))
        except (OSError, PermissionError):
            pass

        # Set readline behavior
        readline.set_history_length(5000)
        if "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

        # Show banner
        p, v, c = _get_stats()
        self.intro = _banner(p, v, c)

    def postloop(self):
        """Save history on exit."""
        try:
            readline.write_history_file(str(self._history_file))
        except (OSError, PermissionError):
            pass

    def postcmd(self, stop, line):
        """Update prompt after every command (project may have changed)."""
        self._update_prompt()
        return stop

    # ── Command dispatch ──────────────────────────────────────────

    def default(self, line: str):
        """Dispatch any command to the CLI handler."""
        line = line.strip()
        if not line:
            return

        # Handle aliases
        first_word = line.split()[0]
        if first_word in _ALIASES:
            alias_expansion = _ALIASES[first_word]
            if alias_expansion == "?":
                return self.do_help("")
            rest = line[len(first_word):].strip()
            line = f"{alias_expansion} {rest}".strip()

        # Parse and dispatch
        try:
            args = self._parser.parse_args(shlex.split(line))
        except SystemExit:
            # argparse calls sys.exit on --help or bad args; swallow it
            return
        except ValueError as e:
            print(f"  Parse error: {e}")
            return

        if not args.command:
            return

        handler = COMMAND_MAP.get(args.command)
        if not handler:
            print(f"  Unknown command: {args.command}")
            return

        try:
            handler(args)
        except KeyboardInterrupt:
            print("\n  Interrupted.")
        except SystemExit:
            pass
        except Exception as e:
            msg = str(e)
            if "FOREIGN KEY constraint failed" in msg:
                msg = "Referenced project/target/vuln does not exist. Check the ID."
            elif "UNIQUE constraint failed" in msg:
                msg = f"Duplicate entry: {msg}"
            print(f"\n  ❌ Error: {msg}")

    # ── Built-in console commands ─────────────────────────────────

    def do_quit(self, _arg):
        """Exit the console."""
        print("  Goodbye.")
        return True

    do_exit = do_quit
    do_EOF = do_quit  # Ctrl+D

    def do_cls(self, _arg):
        """Clear the screen."""
        os.system("clear")

    def do_banner(self, _arg):
        """Show the startup banner."""
        p, v, c = _get_stats()
        print(_banner(p, v, c))

    def do_set(self, arg):
        """Set a context variable: set <key> <value>

Available keys:
    project <id>   — Set the active project (same as 'use <id>')
    no-color on|off — Toggle colored output
"""
        parts = arg.split(None, 1)
        if not parts:
            print("  Usage: set <key> <value>")
            print("  Keys: project, no-color")
            return
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""

        if key == "project":
            if not val:
                print("  Usage: set project <id>")
                return
            try:
                pid = int(val)
                set_active_project(pid)
                from .modules import projects
                p = projects.get_project(pid)
                name = p["name"] if p else f"#{pid}"
                print(f"  [*] project => {pid} ({name})")
            except ValueError:
                print("  Project ID must be a number.")
        elif key in ("no-color", "nocolor", "no_color"):
            on = val.lower() in ("on", "true", "1", "yes")
            set_no_color(on)
            print(f"  [*] no-color => {'on' if on else 'off'}")
        else:
            print(f"  Unknown key: {key}")
            print("  Keys: project, no-color")

    def do_unset(self, arg):
        """Clear a context variable: unset <key>"""
        key = arg.strip().lower()
        if key == "project":
            clear_active_project()
            print("  [*] Active project cleared.")
        else:
            print(f"  Unknown key: {key}")

    def do_shortcuts(self, _arg):
        """Show available command aliases/shortcuts."""
        print("\n  ═══ Shortcuts ═══\n")
        # Group by what they expand to
        for alias, expansion in sorted(_ALIASES.items()):
            if alias not in ("exit", "q", "help", "clear"):
                print(f"    {alias:15s} → {expansion}")
        print()

    # ── Tab completion ────────────────────────────────────────────

    def completenames(self, text, *ignored):
        """Complete top-level command names."""
        all_commands = list(_SUBCOMMANDS.keys())
        all_commands.extend(_ALIASES.keys())
        all_commands.extend(["quit", "exit", "cls", "banner", "set",
                             "unset", "shortcuts", "help"])
        return [c for c in sorted(set(all_commands)) if c.startswith(text)]

    def completedefault(self, text, line, begidx, endidx):
        """Context-aware completion for commands + subcommands."""
        parts = line[:begidx].split()

        if not parts:
            return self.completenames(text)

        cmd_name = parts[0]

        # Resolve alias
        if cmd_name in _ALIASES:
            expanded = _ALIASES[cmd_name].split()
            cmd_name = expanded[0]
            parts = expanded + parts[1:]

        # Level 1: complete subcommand
        if len(parts) == 1 and cmd_name in _SUBCOMMANDS:
            subs = _SUBCOMMANDS[cmd_name]
            return [s for s in subs if s.startswith(text)]

        # Level 2+: context-dependent completion
        if len(parts) >= 2:
            subcmd = parts[1] if len(parts) > 1 else ""

            # recon run <tool>
            if cmd_name == "recon" and subcmd == "run":
                return [t for t in _RECON_TOOLS if t.startswith(text)]

            # workflow run <name> / workflow preflight <name>
            if cmd_name == "workflow" and subcmd in ("run", "preflight", "show"):
                return [w for w in _WORKFLOW_NAMES if w.startswith(text)]

            # Severity completions
            if "--severity" in parts or "-s" in parts:
                sevs = ["critical", "high", "medium", "low", "informational"]
                return [s for s in sevs if s.startswith(text)]

            # Tool name for ingest --tool
            if cmd_name == "ingest" and "--tool" in parts:
                from .modules.parsers import list_parsers
                tools = list_parsers()
                return [t for t in tools if t.startswith(text)]

            # Format completions
            if "--format" in parts:
                fmts = ["markdown", "html", "pdf", "json"]
                return [f for f in fmts if f.startswith(text)]

            # set <key>
            if cmd_name == "set" and len(parts) == 1:
                keys = ["project", "no-color"]
                return [k for k in keys if k.startswith(text)]

            # Flags starting with --
            if text.startswith("-"):
                # Common flags
                flags = ["--help", "--json", "--no-color", "--project",
                         "--target", "--severity", "--status", "--type",
                         "--tool", "--dry-run", "--args", "--auto",
                         "--port", "--service", "--limit", "--output"]
                return [f for f in flags if f.startswith(text)]

        return []

    # ── Help override ─────────────────────────────────────────────

    def do_help(self, arg):
        """Show help for a command, or list all commands."""
        if arg:
            # Dispatch to argparse help
            try:
                self._parser.parse_args(shlex.split(arg) + ["--help"])
            except SystemExit:
                pass
            return

        print("""
  \033[1m═══ BBRadar Console ═══\033[0m

  \033[1;36mProject & Context\033[0m
    use <id>                    Set active project
    use --clear                 Clear active project
    set project <id>            Same as 'use'
    status                      Show workspace status
    dashboard                   Combined dashboard

  \033[1;36mRecon & Scanning\033[0m
    recon run <tool> <tid>      Run a tool against a target
    recon tools                 List available tools
    probe <tid>                 Analyze target & suggest follow-ups
    probe <tid> --auto          Auto-run all suggestions
    workflow run <name> <tid>   Run an assessment workflow

  \033[1;36mFindings\033[0m
    vuln create <pid> <title>   Create a finding
    vuln list                   List findings
    ingest file <path> <pid>    Import tool output
    wizard vuln                 Guided vulnerability entry

  \033[1;36mManagement\033[0m
    project                     {create|list|show|update|delete|stats}
    target                      {add|list|import|update|delete}
    scope                       {add|list|check|import|overview|wizard}
    report                      {vuln|full|executive|list}
    evidence                    {stats|orphans|cleanup}

  \033[1;36mHackerOne\033[0m
    h1 auth                     Authenticate with HackerOne
    h1 programs | import        Browse & import programs
    h1 reports | earnings       View reports & earnings
    h1 monitor | watch | intel  Monitoring & intelligence

  \033[1;36mKnowledge Base\033[0m
    kb sync                     Sync knowledge base data
    kb search <query>           Search CWE, CAPEC, VRT
    kb cve <id> | kev | enrich  CVE lookup, KEV, enrichment

  \033[1;36mConsole\033[0m
    help <command>              Show help for a command
    shortcuts                   Show aliases
    cls                         Clear screen
    banner                      Show banner
    exit / quit / Ctrl+D        Exit console

  \033[0;90mTab-complete works on commands, subcommands, tool names, and flags.\033[0m
""")


# ═══════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════

def run_console():
    """Launch the interactive BBRadar console."""
    # Ensure BBRadar is initialized
    from .core.database import init_db, get_db_path
    try:
        load_config()
    except Exception:
        print("  BBRadar not initialized. Run 'bb init' first.")
        sys.exit(1)

    try:
        console = BBConsole()
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n  Interrupted. Goodbye.")
        sys.exit(0)
