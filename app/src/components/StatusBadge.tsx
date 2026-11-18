import { cn } from "@/lib/utils";
import type { Status } from "@/lib/api";
import { t } from "@/lib/text";

const look: Record<Status, { dot: string; text: string }> = {
  valid: {
    dot: "bg-emerald-500",
    text: "text-emerald-700 dark:text-emerald-400",
  },
  "expires-soon": {
    dot: "bg-amber-500",
    text: "text-amber-700 dark:text-amber-400",
  },
  expired: {
    dot: "bg-muted-foreground/50",
    text: "text-muted-foreground",
  },
  revoked: {
    dot: "bg-red-500",
    text: "text-red-700 dark:text-red-400",
  },
};

/** A coloured dot and a word: where a certificate stands. */
export function StatusBadge({ status, className }: { status: Status; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-medium", look[status].text, className)}>
      <span className={cn("size-1.5 rounded-full", look[status].dot)} aria-hidden />
      {t.status[status]}
    </span>
  );
}
