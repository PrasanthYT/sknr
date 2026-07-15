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

## Planned build order

1. Demo npm monorepo fixture.
2. npm dependency scanner.
3. service topology graph from `sknr.config.yaml`.
4. OSV + CISA KEV threat-intel cache.
5. lightweight reachability signal.
6. AI-backed priority buckets.
7. remediation planner.
8. Codex executor.
9. verification loop.
10. dashboard.
11. static HTML report.

