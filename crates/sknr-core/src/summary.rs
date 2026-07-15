use crate::model::{PriorityBucket, ScanReport};
use crate::remediation::RemediationPlan;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub services: usize,
    pub packages: usize,
    pub vulnerable_packages: usize,
    pub advisories: usize,
    pub kev_matches: usize,
    pub reachable_packages: usize,
    pub remediation_plans: usize,
    pub fix_now: usize,
    pub this_sprint: usize,
    pub monitor: usize,
}

pub fn build_dashboard_summary(report: &ScanReport, plans: &[RemediationPlan]) -> DashboardSummary {
    let mut fix_now = 0;
    let mut this_sprint = 0;
    let mut monitor = 0;

    for package in &report.inventory {
        match package.priority.as_ref().map(|priority| priority.bucket) {
            Some(PriorityBucket::FixNow) => fix_now += 1,
            Some(PriorityBucket::ThisSprint) => this_sprint += 1,
            Some(PriorityBucket::Monitor) => monitor += 1,
            None => {}
        }
    }

    DashboardSummary {
        services: report.services.len(),
        packages: report.inventory.len(),
        vulnerable_packages: report
            .inventory
            .iter()
            .filter(|package| !package.advisories.is_empty())
            .count(),
        advisories: report
            .inventory
            .iter()
            .map(|package| package.advisories.len())
            .sum(),
        kev_matches: report
            .inventory
            .iter()
            .flat_map(|package| package.advisories.iter())
            .filter(|advisory| advisory.kev_match.is_some())
            .count(),
        reachable_packages: report
            .inventory
            .iter()
            .filter(|package| {
                package
                    .used_by
                    .iter()
                    .any(|usage| usage.reachability.imported)
            })
            .count(),
        remediation_plans: plans.len(),
        fix_now,
        this_sprint,
        monitor,
    }
}
