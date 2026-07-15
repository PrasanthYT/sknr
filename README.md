# Sknr

Sknr is a self-hosted security remediation prototype. The initial build targets one real npm monorepo fixture, scans dependencies, enriches findings with threat intelligence, prioritizes risk, plans fixes, and later executes/verifies remediation.

## Repository layout

```text
crates/
  sknr-core/        Rust domain models and scanner logic
  sknr-cli/         CLI entrypoint
web/
  dashboard/         Future React/Vite dashboard
fixtures/
  demo-monorepo/     Vulnerable npm demo repo scanned by Sknr
docs/                Product and architecture notes
```

## Implementation checklist

- [x] Demo npm monorepo fixture. ✅
- [x] npm dependency scanner. ✅
- [x] service topology graph from `sknr.config.yaml`. ✅
- [x] OSV + CISA KEV threat-intel cache. ✅
- [ ] lightweight reachability signal.
- [ ] AI-backed priority buckets.
- [ ] remediation planner.
- [ ] Codex executor.
- [ ] verification loop.
- [ ] dashboard.
- [ ] static HTML report.
