"use client"

import { useEffect, useMemo, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  Boxes,
  CheckCircle2,
  Loader2,
  Network,
  Package,
  RefreshCw,
  Shield,
  Terminal,
  Wifi,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { loadDashboard, loadFixDryRun, sknrApiBase } from "@/lib/sknr-api"
import type {
  DashboardPayload,
  InventoryPackage,
  PriorityBucket,
  RemediationPlan,
  ScannedService,
} from "@/lib/sknr-types"

const priorityLabels: Record<PriorityBucket, string> = {
  fix_now: "Fix now",
  this_sprint: "This sprint",
  monitor: "Monitor",
}

const priorityTones: Record<
  PriorityBucket,
  "danger" | "warning" | "success"
> = {
  fix_now: "danger",
  this_sprint: "warning",
  monitor: "success",
}

export default function Page() {
  const [data, setData] = useState<DashboardPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedPlan, setSelectedPlan] = useState<RemediationPlan | null>(null)
  const [dryRun, setDryRun] = useState<RemediationPlan | null>(null)
  const [dryRunLoading, setDryRunLoading] = useState(false)

  async function refresh() {
    setLoading(true)
    setError(null)
    try {
      const payload = await loadDashboard()
      setData(payload)
      setSelectedPlan(payload.plans[0] ?? null)
      setDryRun(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "failed to load dashboard")
    } finally {
      setLoading(false)
    }
  }

  async function previewDryRun(plan: RemediationPlan) {
    setDryRunLoading(true)
    setError(null)
    try {
      setDryRun(await loadFixDryRun(plan))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "failed to preview fix")
    } finally {
      setDryRunLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false

    loadDashboard()
      .then((payload) => {
        if (cancelled) return
        setData(payload)
        setSelectedPlan(payload.plans[0] ?? null)
      })
      .catch((cause) => {
        if (cancelled) return
        setError(
          cause instanceof Error ? cause.message : "failed to load dashboard"
        )
      })
      .finally(() => {
        if (cancelled) return
        setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const vulnerablePackages = useMemo(
    () =>
      data?.scan.inventory
        .filter((item) => item.advisories.length > 0)
        .sort((left, right) => {
          const leftRank = priorityRank(left.priority?.bucket)
          const rightRank = priorityRank(right.priority?.bucket)
          return leftRank - rightRank || right.advisories.length - left.advisories.length
        }) ?? [],
    [data]
  )

  const externalEdges = data?.scan.topology.edges ?? []
  const activePlan = dryRun ?? selectedPlan

  return (
    <main className="min-h-svh bg-muted/30">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-5 py-6 lg:px-8">
        <section className="overflow-hidden rounded-3xl border bg-card shadow-sm">
          <div className="grid gap-6 p-6 lg:grid-cols-[1.5fr_1fr] lg:p-8">
            <div className="flex flex-col justify-between gap-8">
              <div className="space-y-4">
                <Badge tone="muted" className="w-fit">
                  Sknr security command center
                </Badge>
                <div className="space-y-3">
                  <h1 className="max-w-3xl text-3xl font-semibold tracking-tight md:text-5xl">
                    Dependency risk mapped to services, reachability, and fixes.
                  </h1>
                  <p className="max-w-2xl text-sm text-muted-foreground md:text-base">
                    Live Next.js dashboard backed by the Rust scanner API. It maps
                    npm inventory, OSV/CISA enrichment, service topology, AI
                    priority buckets, and remediation plans into one workflow.
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button onClick={refresh} disabled={loading} size="lg">
                  {loading ? (
                    <Loader2 className="animate-spin" />
                  ) : (
                    <RefreshCw />
                  )}
                  Refresh scan
                </Button>
                <span className="rounded-full border bg-background px-3 py-1.5 font-mono text-xs text-muted-foreground">
                  API {sknrApiBase()}
                </span>
              </div>
            </div>
            <Card className="border-dashed">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="size-4" />
                  Backend mapping
                </CardTitle>
                <CardDescription>
                  The UI calls the same endpoints used by automation.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-2 font-mono text-xs">
                  <Endpoint path="/api/dashboard" label="single UI payload" />
                  <Endpoint path="/api/summary" label="executive counters" />
                  <Endpoint path="/api/scan" label="inventory + topology" />
                  <Endpoint path="/api/plans" label="remediation planner" />
                  <Endpoint path="/api/fix/dry-run" label="Codex task preview" />
                </div>
              </CardContent>
            </Card>
          </div>
        </section>

        {error ? (
          <Card className="border-red-500/30 bg-red-500/5">
            <CardContent className="flex items-start gap-3 p-5 text-sm">
              <AlertTriangle className="mt-0.5 size-4 text-red-500" />
              <div>
                <div className="font-medium">Dashboard API error</div>
                <div className="text-muted-foreground">{error}</div>
              </div>
            </CardContent>
          </Card>
        ) : null}

        <SummaryGrid data={data} loading={loading} />

        <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <TopologyCard
            services={data?.scan.services ?? []}
            edgeCount={externalEdges.length}
            loading={loading}
          />
          <PriorityCard data={data} loading={loading} />
        </div>

        <div className="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
          <FindingsCard packages={vulnerablePackages} loading={loading} />
          <PlannerCard
            plans={data?.plans ?? []}
            selectedPlan={selectedPlan}
            activePlan={activePlan}
            loading={loading}
            dryRunLoading={dryRunLoading}
            onSelect={(plan) => {
              setSelectedPlan(plan)
              setDryRun(null)
            }}
            onPreview={previewDryRun}
          />
        </div>
      </div>
    </main>
  )
}

function SummaryGrid({
  data,
  loading,
}: {
  data: DashboardPayload | null
  loading: boolean
}) {
  const summary = data?.summary
  const cards = [
    {
      label: "Services",
      value: summary?.services,
      icon: Network,
      detail: "from sknr.config.yaml",
    },
    {
      label: "Packages",
      value: summary?.packages,
      icon: Package,
      detail: "lockfile inventory",
    },
    {
      label: "Vulnerable",
      value: summary?.vulnerable_packages,
      icon: AlertTriangle,
      detail: `${summary?.advisories ?? 0} advisories`,
    },
    {
      label: "KEV matches",
      value: summary?.kev_matches,
      icon: Wifi,
      detail: "CISA known exploited",
    },
    {
      label: "Reachable",
      value: summary?.reachable_packages,
      icon: CheckCircle2,
      detail: "import signal found",
    },
    {
      label: "Plans",
      value: summary?.remediation_plans,
      icon: Bot,
      detail: "Codex-ready tasks",
    },
  ]

  return (
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
      {cards.map((card) => (
        <Card key={card.label}>
          <CardContent className="p-5">
            <div className="mb-5 flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{card.label}</span>
              <card.icon className="size-4 text-muted-foreground" />
            </div>
            <div className="text-3xl font-semibold tracking-tight">
              {loading ? "—" : card.value}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">{card.detail}</div>
          </CardContent>
        </Card>
      ))}
    </section>
  )
}

function TopologyCard({
  services,
  edgeCount,
  loading,
}: {
  services: ScannedService[]
  edgeCount: number
  loading: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="size-4" />
          Service topology
        </CardTitle>
        <CardDescription>
          Internet exposure and service dependency density from sknr.config.yaml.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <SkeletonRows count={4} />
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-3 rounded-xl border bg-muted/40 p-3">
              <Badge tone="danger">internet</Badge>
              <ArrowRight className="size-4 text-muted-foreground" />
              <span className="text-sm">
                {edgeCount} exposure edge{edgeCount === 1 ? "" : "s"}
              </span>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              {services.map((service) => (
                <div key={service.name} className="rounded-xl border p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium">{service.name}</div>
                      <div className="mt-1 font-mono text-xs text-muted-foreground">
                        {service.path}
                      </div>
                    </div>
                    <Badge tone={service.internet_facing ? "danger" : "muted"}>
                      {service.internet_facing ? "public" : "internal"}
                    </Badge>
                  </div>
                  <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
                    <span>{service.package_name}</span>
                    <span>{service.dependencies.length} deps</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function PriorityCard({
  data,
  loading,
}: {
  data: DashboardPayload | null
  loading: boolean
}) {
  const summary = data?.summary
  const buckets = [
    { bucket: "fix_now" as const, value: summary?.fix_now ?? 0 },
    { bucket: "this_sprint" as const, value: summary?.this_sprint ?? 0 },
    { bucket: "monitor" as const, value: summary?.monitor ?? 0 },
  ]
  const total = buckets.reduce((sum, item) => sum + item.value, 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>AI priority buckets</CardTitle>
        <CardDescription>
          Bucketed risk after advisory, KEV, exposure, and reachability signals.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <SkeletonRows count={3} />
        ) : (
          <div className="space-y-4">
            {buckets.map((item) => (
              <div key={item.bucket} className="space-y-2">
                <div className="flex items-center justify-between">
                  <Badge tone={priorityTones[item.bucket]}>
                    {priorityLabels[item.bucket]}
                  </Badge>
                  <span className="text-sm font-medium">{item.value}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{
                      width: `${total === 0 ? 0 : (item.value / total) * 100}%`,
                    }}
                  />
                </div>
              </div>
            ))}
            <p className="text-sm text-muted-foreground">
              Packages without AI output remain visible in findings and default to
              planner-safe handling on the backend.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function FindingsCard({
  packages,
  loading,
}: {
  packages: InventoryPackage[]
  loading: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Boxes className="size-4" />
          Vulnerable package inventory
        </CardTitle>
        <CardDescription>
          Every advisory-backed npm package, ranked by priority and signal count.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <SkeletonRows count={6} />
        ) : packages.length === 0 ? (
          <EmptyState message="No vulnerable packages returned by the scan." />
        ) : (
          <div className="overflow-hidden rounded-xl border">
            <table className="w-full text-sm">
              <thead className="bg-muted/60 text-left text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Package</th>
                  <th className="px-4 py-3">Signals</th>
                  <th className="px-4 py-3">Services</th>
                  <th className="px-4 py-3">Priority</th>
                </tr>
              </thead>
              <tbody>
                {packages.map((item) => (
                  <tr key={`${item.name}@${item.version}`} className="border-t">
                    <td className="px-4 py-3">
                      <div className="font-medium">{item.name}</div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {item.version}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        <Badge tone="warning">{item.advisories.length} OSV</Badge>
                        {item.advisories.some((advisory) => advisory.kev_match) ? (
                          <Badge tone="danger">KEV</Badge>
                        ) : null}
                        {isReachable(item) ? (
                          <Badge tone="success">reachable</Badge>
                        ) : (
                          <Badge tone="muted">not imported</Badge>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {item.used_by.map((usage) => usage.service).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-3">
                      {item.priority ? (
                        <Badge tone={priorityTones[item.priority.bucket]}>
                          {priorityLabels[item.priority.bucket]}
                        </Badge>
                      ) : (
                        <Badge tone="muted">Unprioritized</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function PlannerCard({
  plans,
  selectedPlan,
  activePlan,
  loading,
  dryRunLoading,
  onSelect,
  onPreview,
}: {
  plans: RemediationPlan[]
  selectedPlan: RemediationPlan | null
  activePlan: RemediationPlan | null
  loading: boolean
  dryRunLoading: boolean
  onSelect: (plan: RemediationPlan) => void
  onPreview: (plan: RemediationPlan) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Terminal className="size-4" />
          Remediation planner
        </CardTitle>
        <CardDescription>
          Plans are returned by `/api/plans`; dry-run maps one plan to Codex scope.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <SkeletonRows count={5} />
        ) : plans.length === 0 ? (
          <EmptyState message="No remediation plans are currently available." />
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              {plans.map((plan) => (
                <button
                  key={`${plan.package}-${plan.current_version}`}
                  className={`w-full rounded-xl border p-3 text-left transition hover:bg-muted/60 ${
                    selectedPlan?.package === plan.package
                      ? "border-primary bg-muted/50"
                      : "bg-background"
                  }`}
                  onClick={() => onSelect(plan)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{plan.package}</span>
                    <Badge tone={priorityTones[plan.priority_bucket]}>
                      {priorityLabels[plan.priority_bucket]}
                    </Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <span>
                      {plan.current_version} → {plan.target_version}
                    </span>
                    <span>{plan.upgrade_risk} upgrade</span>
                  </div>
                </button>
              ))}
            </div>

            {selectedPlan ? (
              <Button
                variant="outline"
                className="w-full"
                onClick={() => onPreview(selectedPlan)}
                disabled={dryRunLoading}
              >
                {dryRunLoading ? <Loader2 className="animate-spin" /> : <Bot />}
                Preview Codex dry-run task
              </Button>
            ) : null}

            {activePlan ? (
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <div className="font-medium">{activePlan.package}</div>
                    <div className="text-xs text-muted-foreground">
                      Services: {activePlan.services.join(", ")}
                    </div>
                  </div>
                  <Badge tone="muted">Codex task</Badge>
                </div>
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-background p-3 font-mono text-xs leading-relaxed text-muted-foreground">
                  {activePlan.codex_task}
                </pre>
              </div>
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function Endpoint({ path, label }: { path: string; label: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border bg-background px-3 py-2">
      <span>{path}</span>
      <span className="text-muted-foreground">{label}</span>
    </div>
  )
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }, (_, index) => (
        <div
          key={index}
          className="h-12 animate-pulse rounded-xl bg-muted"
        />
      ))}
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">
      {message}
    </div>
  )
}

function isReachable(item: InventoryPackage) {
  return item.used_by.some((usage) => usage.reachability.imported)
}

function priorityRank(bucket?: PriorityBucket) {
  if (bucket === "fix_now") return 0
  if (bucket === "this_sprint") return 1
  if (bucket === "monitor") return 2
  return 3
}
