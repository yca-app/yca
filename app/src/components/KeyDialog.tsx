import { useEffect, useState } from "react";
import { Check, LoaderCircle, TriangleAlert } from "lucide-react";

import { KeyName } from "@/components/KeyTag";
import { Secret } from "@/components/Secret";
import { explain } from "@/components/SigningDialog";
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
import { Label } from "@/components/ui/label";
import { api, type CaRole, type Device, type Failure } from "@/lib/api";
import { commonName, t } from "@/lib/text";

/**
 * What can be done to a YubiKey's own credentials:
 * - `protect`: a PIN and a PUK in place of the factory ones,
 * - `change`: another PIN, for someone who knows the one it has,
 * - `unblock`: a new PIN by way of the PUK, when the PIN is lost or locked,
 * - `reset`: back to the factory state, when both are lost or to start over.
 */
export type KeyTask = "protect" | "change" | "unblock" | "reset";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The YubiKey and what is to be done to it. Kept while the dialog
   *  fades out, so its words do not change. */
  device: Device | null;
  task: KeyTask;
  /** Which CA of the open workspace lives on this YubiKey, if one does:
   *  what a reset would cost. */
  workspaceRole: CaRole | null;
  /** Called once the YubiKey has done it. */
  onDone: () => void;
}

/**
 * The PIN, the PUK and the reset of one YubiKey. WRITES TO THE YUBIKEY:
 * the first three only its PIN and PUK, leaving the CA on it as it is;
 * the reset everything in the key's certificate store.
 */
export function KeyDialog({ open, onOpenChange, device, task, workspaceRole, onDone }: Props) {
  const [current, setCurrent] = useState("");
  const [pin, setPin] = useState("");
  const [pinRepeat, setPinRepeat] = useState("");
  const [puk, setPuk] = useState("");
  const [pukRepeat, setPukRepeat] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The YubiKey has done it. The dialog says so before it goes, instead
  // of vanishing and leaving its user to wonder whether it worked.
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!open) return;
    setDone(false);
    setCurrent("");
    setPin("");
    setPinRepeat("");
    setPuk("");
    setPukRepeat("");
    setConfirmation("");
    setError(null);
  }, [open, task]);

  // A changed PIN needs no more than a glance, so the dialog closes by
  // itself. After a reset it stays: it says what the PIN is now.
  useEffect(() => {
    if (!open || !done || task === "reset") return;
    const timer = window.setTimeout(() => onOpenChange(false), 2000);
    return () => window.clearTimeout(timer);
  }, [open, done, task, onOpenChange]);

  const lengthOk = (value: string) => value.length >= 6 && value.length <= 8;
  const pinsDiffer = pinRepeat !== "" && pin !== pinRepeat;
  const puksDiffer = task === "protect" && pukRepeat !== "" && puk !== pukRepeat;
  const newPinOk = lengthOk(pin) && pin === pinRepeat;
  const ready =
    task === "protect"
      ? newPinOk && lengthOk(puk) && puk === pukRepeat
      : task === "change"
        ? lengthOk(current) && newPinOk
        : task === "unblock"
          ? lengthOk(puk) && newPinOk
          : device !== null && confirmation.trim() === String(device.serial);

  async function run() {
    if (!device) return;
    const serial = device.serial;
    setBusy(true);
    setError(null);
    try {
      if (task === "protect") await api.protectKey({ serial, newPin: pin, newPuk: puk });
      else if (task === "change") await api.changePin({ serial, currentPin: current, newPin: pin });
      else if (task === "unblock") await api.unblockPin({ serial, puk, newPin: pin });
      else await api.resetKey(serial);
      setDone(true);
    } catch (reason) {
      const failure = reason as Failure;
      setError(explain(failure));
      // What was refused is typed again; what was chosen stays.
      if (failure.kind === "wrong-pin") setCurrent("");
      if (failure.kind === "wrong-puk") setPuk("");
    } finally {
      setBusy(false);
      // The key is looked at again either way: a wrong PIN or PUK has
      // cost an attempt, and the window should say so.
      onDone();
    }
  }

  const words = t.key[task];
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      {/* A click beside the dialog does not throw away what was typed. */}
      <DialogContent
        className="sm:max-w-[calc(30rem+6px)]"
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{words.title}</DialogTitle>
          <DialogDescription>{device && <KeyName serial={device.serial} />}</DialogDescription>
        </DialogHeader>
        {done && (
          <p
            role="status"
            className="flex items-start gap-2.5 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-sm font-medium text-emerald-700 dark:text-emerald-400"
          >
            <Check className="mt-0.5 size-4 shrink-0" />
            {words.done}
          </p>
        )}
        <form
          id="key"
          className={done ? "hidden" : "flex flex-col gap-3"}
          onSubmit={(event) => {
            event.preventDefault();
            if (ready && !busy) void run();
          }}
        >
          <p className="text-sm text-muted-foreground">{words.about}</p>

          {task === "reset" && device && (
            <div className="flex flex-col gap-1.5 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2.5 text-sm">
              {device.ca && (
                <p className="flex items-start gap-2 text-destructive">
                  <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                  <span>
                    {t.keyHolds(t.roleInText[device.ca.role], commonName(device.ca.subject))}{" "}
                    {workspaceRole && t.key.reset.ofWorkspace[workspaceRole]}
                  </span>
                </p>
              )}
              {device.otherSlots.length > 0 && (
                <p className="text-destructive">{t.key.reset.otherSlots(device.otherSlots)}</p>
              )}
              <Label htmlFor="key-serial" className="font-normal">
                {t.destroyConfirm(device.serial)}
              </Label>
              <Input
                id="key-serial"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                inputMode="numeric"
                autoComplete="off"
                autoFocus
                className="w-44 tabular-nums"
              />
            </div>
          )}

          {task !== "reset" && (
            <div className="grid grid-cols-2 gap-3">
              {task === "change" && (
                <div className="col-span-2 grid grid-cols-2 gap-3">
                  <Secret
                    label={t.key.currentPin}
                    value={current}
                    onChange={setCurrent}
                    autoFocus
                  />
                </div>
              )}
              {task === "unblock" && (
                <div className="col-span-2 grid grid-cols-2 gap-3">
                  <Secret label={t.key.puk} value={puk} onChange={setPuk} autoFocus />
                </div>
              )}
              <Secret
                label={t.newPin}
                value={pin}
                onChange={setPin}
                autoFocus={task === "protect"}
              />
              <Secret
                label={t.newPinRepeat}
                value={pinRepeat}
                onChange={setPinRepeat}
                invalid={pinsDiffer}
              />
              {task === "protect" && (
                <>
                  <Secret label={t.newPuk} value={puk} onChange={setPuk} />
                  <Secret
                    label={t.newPukRepeat}
                    value={pukRepeat}
                    onChange={setPukRepeat}
                    invalid={puksDiffer}
                  />
                </>
              )}
            </div>
          )}

          {task !== "reset" && (
            <p className="text-xs text-muted-foreground">
              {pinsDiffer || puksDiffer ? (
                <span className="text-destructive">{t.credentialsDiffer}</span>
              ) : (pin !== "" && !lengthOk(pin)) ||
                (task === "protect" && puk !== "" && !lengthOk(puk)) ? (
                <span className="text-destructive">{t.credentialLength}</span>
              ) : task === "protect" ? (
                t.newCredentialsHint
              ) : (
                t.key.newPinHint
              )}
            </p>
          )}

          {error && (
            <p className="selectable flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <TriangleAlert className="mt-0.5 size-4 shrink-0" />
              {error}
            </p>
          )}
        </form>
        <DialogFooter>
          {done ? (
            <Button autoFocus onClick={() => onOpenChange(false)}>
              {t.done}
            </Button>
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
              <Button
                type="submit"
                form="key"
                variant={task === "reset" ? "destructive" : "default"}
                disabled={!ready || busy}
              >
                {busy && <LoaderCircle className="animate-spin" />}
                {words.confirm}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
