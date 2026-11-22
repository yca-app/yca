import { useEffect, useState } from "react";
import { LoaderCircle, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api, type Certificate, type Pki } from "@/lib/api";
import { t } from "@/lib/text";
import { cn } from "@/lib/utils";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The certificates to sort. Kept while the dialog fades out. */
  certificates: Certificate[];
  /** The groups the workspace has. */
  groups: string[];
  path: string;
  /** Called with the workspace as it is afterwards. */
  onDone: (pki: Pki) => void;
}

/**
 * Sorts one certificate or several into a group, or takes them out of
 * theirs. Needs no YubiKey: nothing is signed, the certificates' folders
 * move inside the workspace.
 */
export function GroupDialog({ open, onOpenChange, certificates, groups, path, onDone }: Props) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // What they are in now, if it is the same for all of them.
  const current =
    certificates.length > 0 && certificates.every((c) => c.group === certificates[0].group)
      ? certificates[0].group
      : null;
  useEffect(() => {
    if (!open) return;
    setName(current ?? "");
    setError(null);
  }, [open, current]);

  const tidy = name.trim().replace(/\s+/g, " ");
  const grouped = certificates.some((certificate) => certificate.group !== null);
  // Nothing to do: no name and none of them in a group, or the group
  // they are all in already.
  const pointless =
    tidy === ""
      ? !grouped
      : certificates.every(
          (certificate) => certificate.group?.toLowerCase() === tidy.toLowerCase(),
        );

  async function run() {
    setBusy(true);
    setError(null);
    try {
      onDone(
        await api.setGroup(
          path,
          certificates.map((certificate) => certificate.serial),
          tidy === "" ? null : tidy,
        ),
      );
      onOpenChange(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      {/* A click beside the dialog does not throw away what was typed. */}
      <DialogContent
        className="sm:max-w-[calc(28rem+6px)]"
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t.group.moveTitle}</DialogTitle>
          <DialogDescription className="truncate">
            {certificates.length === 1
              ? certificates[0].names.join(", ")
              : t.group.certificates(certificates.length)}
          </DialogDescription>
        </DialogHeader>
        <form
          id="group"
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!pointless && !busy) void run();
          }}
        >
          <Input
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={60}
            placeholder={t.group.namePlaceholder}
            aria-label={t.group.namePlaceholder}
          />
          {groups.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {groups.map((group) => (
                <button
                  key={group}
                  type="button"
                  onClick={() => setName(group)}
                  className={cn(
                    "max-w-full truncate rounded-md border px-2 py-1 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
                    group.toLowerCase() === tidy.toLowerCase()
                      ? "border-transparent bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {group}
                </button>
              ))}
            </div>
          )}
          <p className="text-xs text-muted-foreground">{t.group.moveBody}</p>
          {error && (
            <p className="selectable flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <TriangleAlert className="mt-0.5 size-4 shrink-0" />
              {error}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button
            variant="ghost"
            className="mr-auto"
            disabled={busy}
            onClick={() => onOpenChange(false)}
          >
            {t.cancel}
          </Button>
          <Button type="submit" form="group" disabled={pointless || busy}>
            {busy && <LoaderCircle className="animate-spin" />}
            {tidy === "" && grouped ? t.group.confirmRemove : t.group.confirmMove}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
