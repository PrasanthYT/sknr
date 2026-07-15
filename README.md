# Sknr

Sknr is a self-hosted security remediation prototype. The initial build targets one real npm monorepo fixture, scans dependencies, enriches findings with threat intelligence, prioritizes risk, plans fixes, and later executes/verifies remediation.

## Repository layout

```text
crates/
  sknr-core/        Rust domain models and scanner logic
  sknr-cli/         CLI entrypoint
web/
  dashboard/         Next.js + shadcn/ui security dashboard
fixtures/
  demo-monorepo/     Vulnerable npm demo repo scanned by Sknr
docs/                Product and architecture notes
```

## Implementation checklist

- [x] Demo npm monorepo fixture. ✅
- [x] npm dependency scanner. ✅
- [x] service topology graph from `sknr.config.yaml`. ✅
- [x] OSV + CISA KEV threat-intel cache. ✅
- [x] lightweight reachability signal. ✅
- [x] AI-backed priority buckets. ✅
- [x] remediation planner. ✅
- [x] Codex executor. ✅
- [x] verification loop. ✅
- [x] dashboard.
- [x] static HTML report.

## Product readiness backlog

These are the next product-facing items to start from now that the core prototype is complete:

- [ ] SARIF output for GitHub Code Scanning.
- [ ] CI exit codes based on priority bucket.
- [ ] `sknr init` to generate `sknr.config.yaml`.
- [ ] GitHub PR creation after Codex execution.
- [ ] Better dashboard detail pages.
- [ ] Docker image / GitHub Action.
- [ ] Scan history SQLite tables.
- [ ] SBOM export.

## Worth confirming before submission

- [x] `--openai-model` defaults to GPT-5.6 when no override is provided.
- [x] CISA KEV matching leaves GHSA-only/no-CVE advisories as `kev_match: null` instead of treating them as exploited.
- [ ] Add a license file before positioning the repo as open source.
- [ ] Capture the pre-remediation verification snapshot automatically from the dashboard flow instead of requiring manual `--before before-scan.json` file handling.
