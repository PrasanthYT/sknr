# Sknr — tech stack

## At a glance

| Layer | Choice | Why |
|---|---|---|
| CLI + core engine | Rust (`clap`, `tokio`) | Existing Sknr codebase, single static binary, no runtime to install — matters for a tool that runs inside someone else's CI |
| CI (building Sknr itself) | GitHub Actions, Rust-native | `cargo test`/`clippy`/`fmt` on every push, cross-compiled release binaries |
| CLI's CI-awareness | JSON + SARIF output, exit codes | Lets Sknr gate someone else's pipeline the way a test failure would |
| Storage | SQLite (`rusqlite`) | Zero external dependency — matches the self-hosted, entry-level architecture |
| Threat intel | `reqwest` → OSV API + CISA KEV feed | Real public data, cached for demo speed |
| AI reasoning | GPT-5.6 via OpenAI API, structured output | JSON-schema-constrained so output is always parseable |
| Remediation | Codex CLI/API as a subprocess | Real branch/patch/test, not templated version bumps |
| Web API | `axum` (HTTP + WebSocket) | Same binary/container as the CLI, no separate service |
| Dashboard | Next.js + shadcn/ui-style components + Tailwind | Live scan, topology, priority, and remediation views over the `sknr dashboard` API |
| Report | Rust static renderer | Static, self-contained HTML, no server needed to view it |
| Stretch: GitHub | `octocrab` | Real PR creation against the demo repo |

---

## Core language: Rust — confirmed for CLI and CI

- **Why:** the existing Sknr codebase is already Rust, it compiles to one static binary with no runtime to install (important since this tool is meant to run inside customer CI pipelines, not just on a dev laptop), and it's cross-platform without extra work.
- **CLI framework:** `clap` (derive macros) for subcommands — `scan`, `prioritize`, `attack-path`, `fix`, `plan`, `report` — each supporting a `--json` flag for machine-readable output.
- **Async runtime:** `tokio` — nearly everything the CLI does is I/O bound (OSV lookups, GPT-5.6 calls, Codex subprocess, GitHub API), so an async core pays for itself immediately.

## CI — building and testing Sknr itself

- GitHub Actions workflow: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` on every push and PR.
- Cross-compilation via `cross` or `cargo-zigbuild` to produce Linux/macOS/Windows binaries from a single CI runner.
- Docker build as a multi-stage Dockerfile: stage 1 compiles the Rust binary and builds the React frontend, stage 2 copies both into a minimal runtime image. This is what `docker run sknr/demo` actually ships.
- Tag-triggered release job pushes the image to a registry (Docker Hub or GHCR) so the one-command install works for a judge on demo day without a local build step.

## The CLI's own CI-awareness

This is the part that answers "for the CI" specifically — Sknr isn't just built with CI, it's designed to run inside one:

- `--format json` and `--format sarif` output — SARIF specifically so results can land directly in GitHub's native Code Scanning tab, the same integration path Snyk uses.
- Exit codes tied to priority: a non-zero exit if any "Fix now" finding exists, so `sknr scan` can gate a pipeline exactly like a failing test suite would.
- `--non-interactive` flag disabling any prompt or dashboard auto-launch behavior, since CI runners have no browser to open.

## Storage

SQLite via `rusqlite` — a single file, no external database service. This matches the self-hosted/entry-level architecture decided earlier; Postgres only enters the picture if the enterprise multi-tenant tier ever gets built.

## Threat intelligence

`reqwest` for OSV API calls and the CISA KEV feed. The KEV feed is cached locally and refreshed on an interval rather than fetched live on every scan — pre-warmed specifically before recording the demo video.

## AI layer

- **GPT-5.6:** called directly over `reqwest` using structured/JSON-schema-constrained responses — no dedicated SDK needed for this narrow a use case.
- **Codex:** invoked as a subprocess from the Rust core (`std::process::Command`), with stdout piped so its real output streams live into the dashboard over the WebSocket connection from the API layer below.

## Web API layer

`axum` for HTTP and WebSocket, sharing the same SQLite connection as the CLI. It's a subcommand of the same binary (`sknr dashboard`) rather than a separate service — one container, one process tree, matching the self-hosted diagram from earlier.

## Dashboard

Next.js, Tailwind, and local shadcn/ui-style primitives for the scan summary, service topology, vulnerable package table, priority buckets, and Codex task preview. The app can run against `sknr dashboard` during development or be statically exported and served by the same Rust dashboard command.

## Report generation

Rust rendering code serializes the same `DashboardData` used by the API into one self-contained static HTML file with inlined CSS and embedded JSON — viewable with no server running.

## Stretch: GitHub integration

`octocrab` (Rust GitHub API client) for branch creation and opening the PR, authenticated with a personal access token.

## Testing

`cargo test` for the Rust core, backed by a small fixture set of known-vulnerable `package.json`/lockfile pairs — so scanner correctness in CI doesn't depend on live OSV calls succeeding every run.
