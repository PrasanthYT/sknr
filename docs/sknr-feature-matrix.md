# Sknr — feature matrix

Two tiers, by module. **Entry level** is what Sknr actually runs as a self-hosted, single-repo, open-source tool this week. **Enterprise** is the direction it points toward — the open-source alternative to Snyk's platform — shown for context. Nothing in the enterprise column is built or claimed as built. Keep these two lists separate in the pitch; blending them is the fastest way to lose credibility with a technical judge.

---

## A. Connect & discover

| Module | Entry level | Enterprise |
|---|---|---|
| Repository connection | Personal access token against a single repo. `sknr scan <path>` or `docker run sknr/demo`. No OAuth app, no webhook server. | GitHub/GitLab/Bitbucket/Azure DevOps App install across an org, admin-approval flow, broker-style relay for on-prem/GitHub Enterprise, bulk multi-repo import. |
| Dependency scanning (SCA) | npm/Node.js only. Parses `package.json` + lockfile. Direct OSV API lookups. | 13+ languages, 20+ package managers. Indexed/cached vulnerability database for org-wide scale. Scheduled recurring scans across every connected repo. |
| Security graph & topology | Monorepo folder auto-discovery (`apps/*`) + one `sknr.config.yaml` declaring exposure per service. | Cross-repo service graph auto-built from deployment/infra metadata (Kubernetes manifests, cloud inventory) — a full org service map, not a hand-declared one. |

## B. Understand risk

| Module | Entry level | Enterprise |
|---|---|---|
| Threat intelligence | OSV advisories + CISA KEV, cross-referenced via CVE aliases. | Additional feeds layered in: EPSS exploit-prediction scores, vendor advisories, proprietary in-house vulnerability research. |
| Reachability analysis | Direct-vs-transitive dependency depth + source import grep — a real but lightweight proxy signal. | Full call-graph static analysis engine (DeepCode-style), with human security-researcher verification of root causes over time. |
| GPT-5.6 risk reasoning | One JSON payload per finding → bucketed priority (Fix now / Sprint / Monitor) + a transparent, traceable reasons list. | Org-wide risk-score aggregation, business-impact weighting per service, exec-facing rollup summaries, policy engine (e.g. block merges below a risk threshold). |

## C. Remediate

| Module | Entry level | Enterprise |
|---|---|---|
| Remediation planning | Semver diff → upgrade-risk label (patch / minor / major) with plain-language reasons, no fake confidence score. | Breaking-change impact analysis across every dependent service, staged rollout plans, license-compliance checks bundled into the same plan. |
| Codex execution | Single repo: branch, patch, install, test, stream real logs. Optional PR against the demo repo (stretch goal). | Fleet-wide automated PR generation across every affected repo, policy-gated auto-merge, rollback automation if verification fails post-merge. |
| Verification & monitoring | Manual re-scan (`sknr scan`) diffs before/after vulnerability counts. | `sknr monitor` on a schedule (daily/weekly), webhook-triggered rescans on every PR, drift alerts when new CVEs land against already-shipped code. |

## D. Govern & scale

| Module | Entry level | Enterprise |
|---|---|---|
| Reporting & dashboard | Static `security-report.html` for a single project — a shareable artifact, no login required. | Live web dashboard, org-wide rollups across every repo and team, SBOM export, full audit trail. |
| Code scanning (SAST) | Not built — explicitly out of scope this round. | First-party source vulnerability scanning (mirrors Snyk Code), catching flaws in code you wrote, not just dependencies. |
| Container & IaC scanning | Not built. | Docker/OCI image scanning, Terraform/Kubernetes/CloudFormation misconfiguration detection before deploy. |
| AI agent governance | Not built. | Inventory and runtime governance of AI coding agents and MCP servers touching the codebase — validating what agents install, what they do, and what they produce (the Evo ADS pattern). |
| Access control & compliance | None — single operator, PAT-based, local use only. | SSO/SAML, RBAC, audit logs, a documented path toward SOC 2 / ISO 27001 / HIPAA / PCI posture. |

---

**One-line pitch for this matrix**: Snyk validated every module in the enterprise column — and built it closed. Sknr's entry-level column is a working, transparent, self-hostable seed of the same idea, released open source instead of behind an enterprise contract.
