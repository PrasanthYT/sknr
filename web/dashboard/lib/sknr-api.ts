import type {
  DashboardPayload,
  RemediationPlan,
  ScanHistoryEntry,
  ScanReport,
} from "@/lib/sknr-types"

const DEFAULT_API_BASE = "http://127.0.0.1:4317"

export function sknrApiBase() {
  return process.env.NEXT_PUBLIC_SKNR_API_BASE ?? DEFAULT_API_BASE
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${sknrApiBase()}${path}`, {
    cache: "no-store",
  })

  if (!response.ok) {
    throw new Error(`${path} failed with ${response.status}`)
  }

  return response.json() as Promise<T>
}

export async function loadDashboard(): Promise<DashboardPayload> {
  return getJson<DashboardPayload>("/api/dashboard")
}

export async function loadFixDryRun(
  plan: RemediationPlan
): Promise<RemediationPlan> {
  const response = await fetch(`${sknrApiBase()}/api/fix/dry-run`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      package: plan.package,
      service: plan.services[0],
    }),
  })

  if (!response.ok) {
    throw new Error(`/api/fix/dry-run failed with ${response.status}`)
  }

  return response.json() as Promise<RemediationPlan>
}

export async function loadHistory(): Promise<ScanHistoryEntry[]> {
  return getJson<ScanHistoryEntry[]>("/api/history")
}

export async function loadHistoryScan(id: number): Promise<ScanReport> {
  return getJson<ScanReport>(`/api/history/scan?id=${id}`)
}
