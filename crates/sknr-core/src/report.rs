use crate::model::ScanReport;
use crate::remediation::RemediationPlan;
use crate::summary::{build_dashboard_summary, DashboardSummary};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardData {
    pub summary: DashboardSummary,
    pub scan: ScanReport,
    pub plans: Vec<RemediationPlan>,
    pub latest_history: Option<crate::history::ScanHistoryEntry>,
}

pub fn build_dashboard_data(scan: ScanReport, plans: Vec<RemediationPlan>) -> DashboardData {
    DashboardData {
        summary: build_dashboard_summary(&scan, &plans),
        scan,
        plans,
        latest_history: None,
    }
}

pub fn build_dashboard_data_with_history(
    scan: ScanReport,
    plans: Vec<RemediationPlan>,
    latest_history: Option<crate::history::ScanHistoryEntry>,
) -> DashboardData {
    DashboardData {
        summary: build_dashboard_summary(&scan, &plans),
        scan,
        plans,
        latest_history,
    }
}

pub fn render_static_report(data: &DashboardData) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string(data)?;
    let json_for_script = json.replace("</", "<\\/");
    let summary = &data.summary;
    let rows = data
        .scan
        .inventory
        .iter()
        .filter(|package| !package.advisories.is_empty())
        .map(|package| {
            let services = package
                .used_by
                .iter()
                .map(|usage| usage.service.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let priority = package
                .priority
                .as_ref()
                .map(|priority| format!("{:?}", priority.bucket))
                .unwrap_or_else(|| "Unprioritized".to_string());

            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&package.name),
                escape_html(&package.version),
                package.advisories.len(),
                escape_html(&services),
                escape_html(&priority)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let plans = data
        .plans
        .iter()
        .map(|plan| {
            format!(
                "<li><strong>{}</strong>: {} → {} <span>{:?}</span></li>",
                escape_html(&plan.package),
                escape_html(&plan.current_version),
                escape_html(&plan.target_version),
                plan.upgrade_risk
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sknr security report</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #020617; color: #e2e8f0; }}
    body {{ margin: 0; padding: 40px; }}
    main {{ max-width: 1180px; margin: 0 auto; }}
    .hero {{ border: 1px solid #1e293b; border-radius: 24px; padding: 28px; background: linear-gradient(135deg, #0f172a, #111827); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin: 24px 0; }}
    .card {{ border: 1px solid #1e293b; border-radius: 18px; padding: 18px; background: #0f172a; }}
    .value {{ font-size: 32px; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 18px; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #1e293b; text-align: left; }}
    th {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    section {{ margin-top: 32px; }}
    li {{ margin: 8px 0; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #020617; border: 1px solid #1e293b; border-radius: 16px; padding: 16px; }}
  </style>
</head>
<body>
<main>
  <div class="hero">
    <p>Sknr static report</p>
    <h1>Security posture for {root}</h1>
    <p>Self-contained scan, topology, threat-intel, priority, and remediation summary.</p>
  </div>
  <section class="grid">
    <div class="card"><div class="value">{services}</div><div>Services</div></div>
    <div class="card"><div class="value">{packages}</div><div>Packages</div></div>
    <div class="card"><div class="value">{vulnerable}</div><div>Vulnerable packages</div></div>
    <div class="card"><div class="value">{advisories}</div><div>Advisories</div></div>
    <div class="card"><div class="value">{reachable}</div><div>Reachable packages</div></div>
    <div class="card"><div class="value">{plans_count}</div><div>Remediation plans</div></div>
  </section>
  <section>
    <h2>Vulnerable packages</h2>
    <table>
      <thead><tr><th>Package</th><th>Version</th><th>Advisories</th><th>Services</th><th>Priority</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <section>
    <h2>Remediation plans</h2>
    <ul>{plans}</ul>
  </section>
  <section>
    <h2>Embedded JSON</h2>
    <pre id="data"></pre>
  </section>
</main>
<script type="application/json" id="sknr-data">{json}</script>
<script>
  document.getElementById('data').textContent = JSON.stringify(JSON.parse(document.getElementById('sknr-data').textContent), null, 2);
</script>
</body>
</html>"#,
        root = escape_html(&data.scan.root),
        services = summary.services,
        packages = summary.packages,
        vulnerable = summary.vulnerable_packages,
        advisories = summary.advisories,
        reachable = summary.reachable_packages,
        plans_count = summary.remediation_plans,
        rows = rows,
        plans = plans,
        json = json_for_script
    ))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
