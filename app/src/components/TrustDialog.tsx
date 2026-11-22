import { useEffect, useState } from "react";
import { FileText, TriangleAlert } from "lucide-react";

import { Segmented } from "@/components/Segmented";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api, type Pki } from "@/lib/api";
import { commonName, t } from "@/lib/text";

const platforms = ["macos", "windows", "ios", "android"] as const;
type Platform = (typeof platforms)[number];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pki: Pki;
}

/**
 * How to make a computer or a phone trust this CA: the one file to give
 * it, the root CA certificate, and what to do with that file there.
 *
 * A certificate is of no use on a device that does not trust the CA
 * behind it, and where each system hides that setting is not something
 * anyone remembers. Nothing here needs a YubiKey.
 */
export function TrustDialog({ open, onOpenChange, pki }: Props) {
  const [platform, setPlatform] = useState<Platform>("macos");
  // The root CA certificate as a file for devices, in the workspace.
  const [file, setFile] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let wanted = true;
    setError(null);
    api.rootForDevices(pki.path).then(
      (path) => wanted && setFile(path),
      (reason) => wanted && setError(String(reason)),
    );
    return () => {
      wanted = false;
    };
  }, [open, pki.path]);

  const note = t.trust.note[platform];
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-[calc(36rem+6px)]">
        <DialogHeader>
          <DialogTitle>{t.trust.title}</DialogTitle>
          <DialogDescription>
            {t.role.root} “{commonName(pki.root.subject)}”
          </DialogDescription>
        </DialogHeader>

        <p className="text-sm text-muted-foreground">{t.trust.about}</p>

        <div className="rounded-lg border">
          <div className="flex items-center gap-2.5 px-3 py-2">
            <FileText className="size-4 shrink-0 text-muted-foreground" />
            <span className="min-w-0 flex-1">
              <span className="selectable block truncate font-mono text-sm">
                {file?.split("/").pop() ?? "…"}
              </span>
              <span className="block text-xs text-muted-foreground">{t.trust.fileAbout}</span>
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={file === null}
              onClick={() => file && void api.reveal(file)}
            >
              {t.showInFinder}
            </Button>
          </div>
          {pki.root.sha256 !== "" && (
            <div className="border-t px-3 py-2 text-xs">
              <p className="text-muted-foreground">{t.trust.fingerprints}</p>
              <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <dt className="text-muted-foreground">{t.trust.sha256}</dt>
                <dd className="selectable font-mono break-all">{pki.root.sha256}</dd>
                <dt className="text-muted-foreground">{t.trust.sha1}</dt>
                <dd className="selectable font-mono break-all">{pki.root.sha1}</dd>
              </dl>
            </div>
          )}
        </div>

        {error && (
          <p className="selectable flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            {error}
          </p>
        )}

        <div className="flex flex-col gap-2.5">
          <Segmented
            label={t.trust.where}
            options={platforms.map((value) => ({ value, label: t.trust.platform[value] }))}
            value={platform}
            onChange={setPlatform}
          />
          <ol className="flex list-decimal flex-col gap-1.5 pl-5 text-sm marker:text-muted-foreground">
            {t.trust.steps[platform].map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          {note && <p className="text-xs text-muted-foreground">{note}</p>}
        </div>

        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t.done}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
