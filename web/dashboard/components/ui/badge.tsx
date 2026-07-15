import * as React from "react"

import { cn } from "@/lib/utils"

type BadgeProps = React.ComponentProps<"span"> & {
  tone?: "default" | "danger" | "warning" | "success" | "muted"
}

const tones: Record<NonNullable<BadgeProps["tone"]>, string> = {
  default: "border-primary/20 bg-primary/10 text-primary",
  danger: "border-red-500/20 bg-red-500/10 text-red-600 dark:text-red-300",
  warning:
    "border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  success:
    "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  muted: "border-border bg-muted text-muted-foreground",
}

function Badge({ className, tone = "default", ...props }: BadgeProps) {
  return (
    <span
      data-slot="badge"
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium",
        tones[tone],
        className
      )}
      {...props}
    />
  )
}

export { Badge }
