# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

MS17-010 (EternalBlue) remediation agent. Receives vulnerability alerts from Splunk/Nessus, connects to Windows targets via WinRM, disables SMBv1, and verifies the fix. Python 3.10+.

## Commands

```powershell
# Install dependencies
pip install -r requirements.txt

# Run the agent (fetches alerts from configured Splunk/Nessus sources)
python -m src.main

# Remediate a specific host
python -m src.main --target 192.168.1.100

# Dry run (check status only, no changes)
python -m src.main --dry-run

# Verbose output
python -m src.main --verbose
```

There are no tests yet — `tests/` contains only `__init__.py`. If adding tests, use pytest (already implied by `.gitignore` containing `.pytest_cache/`).

## Configuration

All settings are loaded from environment variables via `python-dotenv` in `config/settings.py`. A `.env` file at the repo root is the expected configuration method. Required variables for operation: `WINRM_USERNAME`, `WINRM_PASSWORD`, and at least one alert source (`SPLUNK_HOST`/`SPLUNK_TOKEN` or `NESSUS_HOST`/`NESSUS_API_KEY`).

## Architecture

The pipeline follows a linear flow: **Alert → Connect → Remediate → Verify**.

- `src/main.py` — CLI entry point (Click). Parses args, sets up Loguru logging, instantiates `RemediationAgent`, prints summary.
- `src/agent.py` — `RemediationAgent` orchestrates the full pipeline. `run()` fetches alerts (or creates a manual one for `--target`), then for each alert: connects via WinRM → runs `SMBv1Remediation` → verifies with `RemediationVerifier`. Returns a results dict with total/success/failed counts.
- `src/alert_handler.py` — `AlertHandler` fetches `VulnerabilityAlert` objects from Splunk (REST search API) and Nessus (plugin ID `97833`). Gracefully skips unconfigured sources. `create_manual_alert()` builds an alert for direct `--target` usage.
- `src/winrm_client.py` — `WinRMClient` wraps `pywinrm`. Provides `run_powershell()` and `run_cmd()` returning `CommandResult` dataclasses. `connect()` tests the session with a simple PS command.
- `src/remediation.py` — `SMBv1Remediation` checks SMBv1 status and disables it via embedded PowerShell scripts (Windows Optional Feature with registry fallback for older OS). Returns `RemediationResult` with status enum (`SUCCESS`, `FAILED`, `ALREADY_FIXED`, `SKIPPED`).
- `src/verification.py` — `RemediationVerifier` confirms the fix through three methods: checking feature/registry/service state, running a targeted Nessus re-scan, and checking SMB port 445 dialect.
- `config/settings.py` — Singleton `Settings` class, all fields from env vars with defaults. Imported everywhere as `from config.settings import settings`.

## Key Patterns

- Imports use absolute paths: `from src.module import Class` and `from config.settings import settings`.
- Data classes (`@dataclass`) are used for structured results (`CommandResult`, `RemediationResult`, `VerificationResult`, `VulnerabilityAlert`).
- Status tracking uses enums (`RemediationStatus`, `VerificationStatus`).
- Logging uses `loguru` throughout (not stdlib `logging`). Use `logger.info/error/warning/success/debug`.
- All remote execution goes through `WinRMClient` — never call `pywinrm` directly from other modules.
