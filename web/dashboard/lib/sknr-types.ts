export type PriorityBucket = "fix_now" | "this_sprint" | "monitor"
export type DependencyRelationship = "direct" | "transitive"
export type UpgradeRisk = "patch" | "minor" | "major"
export type TopologyNodeType = "external" | "service"
export type TopologyEdgeRelationship = "internet_exposure"

export type DashboardSummary = {
  services: number
  packages: number
  vulnerable_packages: number
  advisories: number
  kev_matches: number
  reachable_packages: number
  remediation_plans: number
  fix_now: number
  this_sprint: number
  monitor: number
}

export type ReachabilityEvidence = {
  path: string
  line: number
  snippet: string
}

export type ReachabilitySignal = {
  imported: boolean
  evidence: ReachabilityEvidence[]
}

export type KevMatch = {
  cve_id: string
  vulnerability_name: string
  date_added: string
  due_date: string
  known_ransomware_campaign_use: string
}

export type AdvisorySummary = {
  id: string
  modified: string | null
  aliases: string[]
  cve_aliases: string[]
  kev_match: KevMatch | null
}

export type PriorityAssessment = {
  bucket: PriorityBucket
  reasons: string[]
  model: string
}

export type PackageUsage = {
  service: string
  relationship: DependencyRelationship
  internet_facing: boolean
  reachability: ReachabilitySignal
}

export type InventoryPackage = {
  name: string
  version: string
  relationships: DependencyRelationship[]
  used_by: PackageUsage[]
  advisories: AdvisorySummary[]
  priority: PriorityAssessment | null
}

export type ScannedService = {
  name: string
  path: string
  internet_facing: boolean
  package_name: string
  manifest_path: string
  lockfile_path: string
  dependencies: {
    name: string
    version: string
    relationship: DependencyRelationship
    reachability: ReachabilitySignal
  }[]
}

export type TopologyNode = {
  id: string
  label: string
  node_type: TopologyNodeType
  path: string | null
  internet_facing: boolean | null
}

export type TopologyEdge = {
  from: string
  to: string
  relationship: TopologyEdgeRelationship
}

export type ServiceTopology = {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export type ScanReport = {
  root: string
  topology: ServiceTopology
  inventory: InventoryPackage[]
  services: ScannedService[]
}

export type RemediationPlan = {
  package: string
  current_version: string
  target_version: string
  services: string[]
  priority_bucket: PriorityBucket
  upgrade_risk: UpgradeRisk
  reasons: string[]
  codex_task: string
}

export type DashboardPayload = {
  summary: DashboardSummary
  scan: ScanReport
  plans: RemediationPlan[]
  latest_history: ScanHistoryEntry | null
}

export type ScanHistoryEntry = {
  id: number
  root: string
  created_at: number
  summary: DashboardSummary
}
