# Contributing to BBRadar

Thank you for your interest in contributing to BBRadar! This document provides
guidelines for contributing to the project.

## Code of Conduct

- Be respectful and constructive in all interactions.
- This is a **security tool** — all contributions must align with ethical and
  legal use. See [DISCLAIMER.md](DISCLAIMER.md).

## Getting Started

1. Fork the repository
2. Clone your fork and install in development mode:
   ```bash
   git clone https://github.com/c0re-i5/bbradar.git
   cd bbradar
   pip install -e ".[dev]"
   ```
3. Run the test suite to confirm everything works:
   ```bash
   pytest
   ```

## Development Setup

- **Python 3.10+** required
- **SQLite** (bundled with Python)
- Install dev dependencies: `pip install -e ".[dev]"`
- Optional PDF support: `pip install -e ".[pdf]"`

## Making Changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Add or update tests as appropriate
4. Run the full test suite: `pytest`
5. Ensure code is formatted: `black bbradar/ tests/`
6. Check for lint issues: `ruff check bbradar/ tests/`

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Write a clear description of what the PR does and why
- Include test coverage for new functionality
- Update documentation if the user-facing behavior changes

## Adding Tool Parsers

BBRadar supports ingesting output from security tools. To add a new parser:

1. Create `bbradar/modules/parsers/your_tool.py`
2. Implement a `parse(filepath)` function that returns a list of finding dicts
3. Register the parser in `bbradar/modules/parsers/__init__.py`
4. Add tests in `tests/`

Each finding dict should include: `title`, `severity`, `description`, and
optionally `url`, `cwe`, `evidence`, `recommendation`.

## Adding Workflow Templates

Workflow YAML files live in `bbradar/data/workflows/`. Follow the existing
format — each step should define `name`, `tool`, `command`, and optionally
`description` and `expected_output`.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Python version and OS

## Security Issues

If you discover a security vulnerability in BBRadar itself, please report it
privately rather than opening a public issue. Contact the maintainers directly.

---

Thank you for helping make BBRadar better!
