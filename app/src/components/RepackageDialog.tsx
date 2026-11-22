import { useEffect, useState } from "react";
import { Check, FileKey2, FileText, LoaderCircle, TriangleAlert } from "lucide-react";

import { FilesChoice } from "@/components/FilesChoice";
import { useShortPath } from "@/components/PathTail";
import { SecretInput } from "@/components/Secret";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { api, type Certificate, type Files, type Pki, type Repackaged } from "@/lib/api";
import { t } from "@/lib/text";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The certificate whose files to write. Kept while the dialog fades
   *  out, so its words do not change. */
  certificate: Certificate | null;
  path: string;
  /** Called with the workspace as it is afterwards. */
  onDone: (pki: Pki) => void;
  /** Shows the certificate's folder in Finder. */
  onShow: (folder: string) => void;
}

/**
 * Writes the files of a certificate again in another form, for a device
 * whose upload form turned out to ask for something else than was chosen
 * when it was issued. Nothing is issued and no YubiKey is needed: the
 * certificate and its key are in the workspace. A wrong guess at issuing
 * therefore costs two clicks, not a new certificate.
 */
export function RepackageDialog({ open, onOpenChange, certificate, path, onDone, onShow }: Props) {
  const [files, setFiles] = useState<Files>("fullchain");
  const [opens, setOpens] = useState("");
  const [password, setPassword] = useState("");
  const [passwordRepeat, setPasswordRepeat] = useState("");
  const [compatible, setCompatible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [written, setWritten] = useState<Repackaged | null>(null);
  const folderShown = useShortPath(written?.folder ?? "");

  const current = certificate?.form ?? null;
  const hasKey = certificate?.hasKey ?? false;
  // Where the root CA signed, no intermediate CA comes with it.
  const chain = certificate?.issuedBy === "issuing";
  useEffect(() => {
    if (!open) return;
    // The form it is not in, as the one most likely wanted, among those
    // there are for it.
    setFiles(
      current !== "fullchain" ? "fullchain" : chain ? "separate" : hasKey ? "p12" : "fullchain",
    );
    setOpens("");
    setPassword("");
    setPasswordRepeat("");
    setCompatible(false);
    setError(null);
    setWritten(null);
  }, [open, current, chain, hasKey]);

  // The key of a certificate that is in one file is inside that file.
  const locked = current === "p12";
  // Nothing goes into one file without a key to be in it.
  const intoOne = files === "p12" && hasKey;
  // Signed by the root CA and with no key here, there is one form of
  // files and no other to write them in.
  const onlyOne = !chain && !hasKey;
  // The same form again is no change, unless it is to give the one file
  // another password. Without an intermediate CA, a file for it or none
  // is the same form.
  const same = (!chain && files === "separate" ? "fullchain" : files) === current && !intoOne;
  const ready =
    !same &&
    (!locked || opens !== "") &&
    (!intoOne || (password !== "" && password === passwordRepeat));

  async function run() {
    if (!certificate) return;
    setBusy(true);
    setError(null);
    try {
      const done = await api.repackage({
        path,
        serial: certificate.serial,
        files,
        opens: locked ? opens : null,
        p12Password: intoOne ? password : null,
        p12Compatible: intoOne && compatible,
      });
      onDone(done.pki);
      setWritten(done);
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
        className="sm:max-w-[calc(30rem+6px)]"
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t.repack.title}</DialogTitle>
          <DialogDescription className="truncate">
            {certificate?.names.join(", ")}
          </DialogDescription>
        </DialogHeader>

        {written ? (
          // It says that it worked, and what is there now.
          <div className="flex min-w-0 flex-col gap-3">
            <div className="flex items-center gap-2.5 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-emerald-700 dark:text-emerald-400">
              <Check className="size-4 shrink-0" />
              <span className="font-medium">{t.repack.done}</span>
            </div>
            <ul className="divide-y rounded-lg border">
              {written.files.map((file) => (
                <li key={file.name} className="flex items-start gap-2.5 px-3 py-2">
                  {file.holdsPrivateKey ? (
                    <FileKey2 className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  ) : (
                    <FileText className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                  )}
                  <span>
                    <span className="selectable block font-mono">{file.name}</span>
                    <span className="block text-xs text-muted-foreground">
                      {(chain ? undefined : t.fileFromRoot[file.name]) ?? t.file[file.name] ?? ""}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
            <p
              className="selectable text-xs break-all text-muted-foreground"
              title={written.folder}
            >
              {folderShown}
            </p>
          </div>
        ) : (
          <form
            id="repackage"
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (ready && !busy) void run();
            }}
          >
            <p className="text-muted-foreground">{t.repack.about}</p>
            <div className="flex flex-col gap-1.5">
              <Label>{t.files.title}</Label>
              <FilesChoice
                value={files}
                onChange={setFiles}
                withKey={hasKey}
                chain={chain}
                current={current}
              />
              {!hasKey && (
                <p className="text-xs text-muted-foreground">
                  {onlyOne ? t.repack.onlyOne : t.repack.noKey}
                </p>
              )}
            </div>

            {locked && (
              <div className="flex flex-col gap-1.5">
                <Label>{t.repack.opens}</Label>
                <SecretInput
                  value={opens}
                  onChange={(event) => setOpens(event.target.value)}
                  className="w-64"
                />
                <p className="text-xs text-muted-foreground">{t.repack.opensHint}</p>
              </div>
            )}

            {intoOne && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1.5">
                    <Label>{locked ? t.repack.newPassword : t.p12Password}</Label>
                    <SecretInput
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>{t.p12PasswordRepeat}</Label>
                    <SecretInput
                      value={passwordRepeat}
                      onChange={(event) => setPasswordRepeat(event.target.value)}
                      aria-invalid={passwordRepeat !== "" && password !== passwordRepeat}
                    />
                  </div>
                  <p className="col-span-2 -mt-1 text-xs text-muted-foreground">
                    {passwordRepeat !== "" && password !== passwordRepeat ? (
                      <span className="text-destructive">{t.passwordsDiffer}</span>
                    ) : (
                      t.p12PasswordHint
                    )}
                  </p>
                </div>
                <label className="flex items-start gap-2.5">
                  <Checkbox
                    className="mt-0.5"
                    checked={compatible}
                    onCheckedChange={(checked) => setCompatible(checked === true)}
                  />
                  <span>
                    <span className="block">{t.p12Compatible}</span>
                    <span className="block text-xs text-muted-foreground">
                      {t.p12CompatibleHint}
                    </span>
                  </span>
                </label>
              </>
            )}

            {error && (
              <p className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-destructive">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                {error}
              </p>
            )}
          </form>
        )}

        <DialogFooter>
          {written ? (
            <>
              <Button variant="ghost" className="mr-auto" onClick={() => onShow(written.folder)}>
                {t.showInFinder}
              </Button>
              <Button onClick={() => onOpenChange(false)}>{t.done}</Button>
            </>
          ) : (
            <>
              <Button
                variant="ghost"
                className="mr-auto"
                disabled={busy}
                onClick={() => onOpenChange(false)}
              >
                {t.cancel}
              </Button>
              <Button type="submit" form="repackage" disabled={!ready || busy}>
                {busy && <LoaderCircle className="animate-spin" />}
                {t.repack.confirm}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
