# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-21

Complete interface reconstruction focused on simplicity, transparency and
professional presentation.

### Changed
- **Removed the PySide6 desktop GUI entirely.** The interfaces are now a
  polished CLI plus a local web dashboard (FastAPI, browser-based) --
  no native GUI dependencies, works everywhere Python runs.
- **Removed numeric scores and letter grades entirely.** Results are a
  severity-ranked findings register plus per-header verdicts -- no
  arbitrary numbers.
- Simplified header verdicts to four plain-language statuses:
  **Pass / Warning / Fail / Info** (previously Present / Missing / Weak /
  Misconfigured / Deprecated).
- Findings register no longer contains informational noise; only
  actionable issues appear.
- Restructured into an installable package (`header_checker`) with
  console entry points and `pyproject.toml` packaging.
- Renamed `resources/` to `screenshots/`; verification suite lives in
  `checks/` (run with `pytest`).

### Fixed
- Duplicate findings (a missing CSP header was reported twice).
- `max-age=0` HSTS was classified as "Weak" instead of "Fail".
- Severity filter chips in the UI now actually filter the table.
- Logs are written to a platform-appropriate user state directory
  (override with `HEADER_CHECKER_LOG_DIR`) instead of inside the repo.

### Added
- Local web dashboard: `http-header-checker ui`
- JSON export: `--json report.json`; standalone HTML report: `--html report.html`
- CI severity gate for pipelines: `--fail-on high|medium|low|critical`
- Test suite (pytest), linting (ruff) and GitHub Actions CI.

## [1.1.0]

Packaging and project hygiene release.

## [1.0.0]

Initial release: PySide6 desktop application with header, CSP, cookie,
redirect, TLS and fingerprint analysis.
