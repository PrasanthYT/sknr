# Sknr — build sequence

Each step lists what it covers, the tech stack, and what it depends on. The order isn't arbitrary — each step needs real output from the one before it to build against.

---

### 1. Demo environment
**Covers:** A real npm monorepo (`apps/api-gateway`, `apps/auth-service`, `apps/user-service`, `apps/dashboard`) with intentionally outdated packages carrying real, known CVEs — not fabricated CVE IDs — plus a `sknr.config.yaml` declaring which services are internet-facing. This is the fixture every later step scans, reasons about, and patches. Build it first or nothing else has anything real to point at.
**Tech stack:** npm workspaces (or Turborepo) for the monorepo skeleton; deliberately pinned outdated packages with known GHSA/CVE advisories; plain YAML for the exposure config.
**Depends on:** nothing — this is the foundation.

### 2. Dependency scanner (SCA)
**Covers:** Walks the monorepo, finds every `package.json` + lockfile per service, resolves the full dependency tree including transitive packages, and normalizes it into one internal structure. Node/npm only — no Python or Rust ecosystem support, on purpose.
**Tech stack:** Rust core binary; `serde_json` for manifest parsing; `walkdir` for directory traversal; direct parsing of the npm lockfile format rather than shelling out to `npm` for speed and determinism.
**Depends on:** the demo environment (step 1) to scan against.

### 3. Security graph & topology
**Covers:** Turns the flat service list from step 2 into a real graph — which folder is which service, and which face the internet, read straight from `sknr.config.yaml`. This is what makes "attack path" mean something instead of being decorative.
**Tech stack:** same Rust core; `petgraph` for the in-memory graph; `serde_yaml` for the config file.
**Depends on:** scanner output (step 2).

### 4. Threat intelligence layer
**Covers:** For every dependency + version found, queries OSV for known advisories, then cross-references any CVE alias against the CISA KEV feed. Anything without a CVE alias is marked "not applicable" rather than silently treated as clean.
**Tech stack:** `reqwest` for OSV API calls; a cached copy of the CISA KEV JSON feed refreshed periodically and pre-warmed before recording the demo; results persisted to SQLite so re-scans don't re-hit the network every time.
**Depends on:** the dependency list from step 2.

### 5. Reachability signal
**Covers:** For each flagged dependency, checks whether it's direct or transitive (from lockfile tree depth) and greps the service's source for an actual import of the package. Cheap, real, and honestly labeled — not a claim of full call-graph analysis.
**Tech stack:** same Rust core; `regex` for the import-statement grep across `.js`/`.ts` source files; depth computed directly from the lockfile tree already parsed in step 2.
**Depends on:** scanner (step 2) for the dependency tree.

### 6. GPT-5.6 risk engine
**Covers:** Takes the structured signal set from steps 3–5 (severity, exposure, KEV, reachability) for each finding and returns a priority bucket — Fix now / This sprint / Monitor — plus a short, traceable reasons list that maps back to the input fields. No confidence percentages, no invented numbers.
**Tech stack:** OpenAI API call to GPT-5.6 using structured/JSON-schema-constrained output so reasoning always comes back parseable; called from the Rust core via `reqwest`.
**Depends on:** all of steps 3–5 — first point where every signal actually converges.

### 7. Remediation planner
**Covers:** For anything marked Fix now / This sprint, computes the semver distance to the nearest safe version and labels the upgrade risk (patch/minor/major) with plain-language reasons — this becomes Codex's exact task spec in step 8.
**Tech stack:** `semver` crate for version-diff logic; same GPT-5.6 call pattern as step 6, reused for the reasons text on top of the deterministic semver check.
**Depends on:** the priority output of step 6.

### 8. Codex executor
**Covers:** Takes one remediation plan and executes it for real — creates a branch, bumps the dependency, runs install and test, and streams the actual output live. No fake progress bar. This is the step judges will watch most closely.
**Tech stack:** Codex CLI/API invoked as a subprocess or API call from the Rust core, scoped to the target service directory; `std::process::Command` with piped stdout for live log streaming; `npm install` / `npm test` as the real verification commands.
**Depends on:** the remediation plan (step 7).

### 9. Verification loop
**Covers:** Re-runs the scanner (step 2) and threat-intel lookup (step 4) against the patched repo and diffs before/after vulnerability counts — the actual proof risk went down, not just that a command exited cleanly.
**Tech stack:** reuses steps 2 and 4 directly; before/after snapshots stored in SQLite.
**Depends on:** Codex having made a real change (step 8).

### 10. Dashboard (web UI)
**Covers:** Wraps everything above in a browser UI — results, priority buckets, the attack-path graph as real rendered nodes and edges, and a live log view during remediation. Built after the CLI pipeline works end to end, so there's real data to render instead of a guessed-at shape.
**Tech stack:** a small Rust HTTP/WebSocket server (`axum`) exposing the SQLite-backed state; React + Vite frontend; React Flow for the attack-path graph; Tailwind for styling; WebSocket for streaming Codex's live logs from step 8 into the browser.
**Depends on:** steps 2–9 producing real data.

### 11. HTML security report
**Covers:** A static, shareable export of one scan — graph, priorities, remediation history — opening in any browser with no server running.
**Tech stack:** server-side templating (`Tera`) reusing the dashboard's data layer, output as one self-contained HTML file with inlined CSS.
**Depends on:** the dashboard's data layer (step 10).

---

## Stretch goals — only after 1–11 work end to end

### 12. Auto-opened pull request
**Covers:** Pushes the branch and opens a real PR against the demo repo, closing the loop from "found it" to "here's a mergeable fix."
**Tech stack:** GitHub REST API via a personal access token; `octocrab` (Rust GitHub client) or a direct `reqwest` call for branch + PR creation.
**Depends on:** Codex executor (step 8) having made and tested the change.

### 13. Blast radius
**Covers:** Counts how many other services share the same vulnerable package/version — "fixing this once clears it in N places," the enterprise business-impact framing at zero extra cost.
**Tech stack:** a graph traversal over the `petgraph` structure from step 3 — no new dependencies, purely a query against data you already have.
**Depends on:** the security graph (step 3).
