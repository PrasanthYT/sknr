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

## Install and use as a global CLI

Sknr is intended to work like `codex`: install the binary once, enter any npm workspace, then run `sknr` commands from that project directory.

```bash
cargo install --git https://github.com/PrasanthYT/sknr sknr
```

Then, inside a project:

```bash
sknr init
sknr scan
sknr dashboard
sknr report
```

Every project path defaults to the current directory. You can still pass an explicit path when scanning another repo:

```bash
sknr scan ../some-other-project
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

- [x] SARIF output for GitHub Code Scanning.
- [x] CI exit codes based on priority bucket.
- [x] `sknr init` to generate `sknr.config.yaml`.
- [x] GitHub PR creation after Codex execution.
- [x] Better dashboard detail pages.
- [x] Docker image / GitHub Action.
- [x] Scan history SQLite tables.
- [x] SBOM export.

## Product readiness commands

```bash
sknr init
sknr scan --format sarif --fail-on fix-now
sknr scan --save-history
sknr history list
sknr sbom --out bom.json
sknr fix --package lodash --service api-gateway --execute --create-pr --repo owner/repo
```

## Worth confirming before submission

- [x] `--openai-model` defaults to GPT-5.6 when no override is provided.
- [x] CISA KEV matching leaves GHSA-only/no-CVE advisories as `kev_match: null` instead of treating them as exploited.
- [ ] Add a license file before positioning the repo as open source.
- [ ] Capture the pre-remediation verification snapshot automatically from the dashboard flow instead of requiring manual `--before before-scan.json` file handling.
