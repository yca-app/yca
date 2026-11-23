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
import { cn } from "@/lib/utils";

/**
 * What can be done to a YubiKey's own credentials:
 * - `protect`: a PIN and a PUK in place of the factory ones,
 * - `change`: another PIN, for someone who knows the one it has,
 * - `unblock`: a new PIN by way of the PUK, when the PIN is lost or locked,
 * - `finish`: a PUK in place of the factory one, and a management key in
 *   place of the factory one, for a key whose PIN is its owner's already,
 * - `reset`: back to the factory state, when both are lost or to start over.
 */
export type KeyTask = "protect" | "change" | "unblock" | "finish" | "reset";

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
  // Whether `finish` gives the key a PUK, or only a management key. Taken
  // from the key as the dialog comes up: once it is done the key says
  // otherwise, and the dialog must not change its words for that.
  const [withPuk, setWithPuk] = useState(false);

  useEffect(() => {
    if (!open) return;
    setDone(false);
    setWithPuk(device?.factoryPuk ?? false);
    setCurrent("");
    setPin("");
    setPinRepeat("");
    setPuk("");
    setPukRepeat("");
    setConfirmation("");
    setError(null);
    // Not on `device`: the dialog starts over when it comes up, not
    // whenever the key is looked at again.
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
  // The tasks that set a PUK, typed twice.
  const setsPuk = task === "protect" || (task === "finish" && withPuk);
  const puksDiffer = setsPuk && pukRepeat !== "" && puk !== pukRepeat;
  const newPinOk = lengthOk(pin) && pin === pinRepeat;
  const newPukOk = lengthOk(puk) && puk === pukRepeat;
  const ready =
    task === "protect"
      ? newPinOk && newPukOk
      : task === "change"
        ? lengthOk(current) && newPinOk
        : task === "unblock"
          ? lengthOk(puk) && newPinOk
          : task === "finish"
            ? lengthOk(current) && (!withPuk || newPukOk)
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
      else if (task === "finish")
        await api.finishProtecting({ serial, pin: current, newPuk: withPuk ? puk : null });
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

  // What is wrong with what was typed so far, if anything is.
  const amiss =
    pinsDiffer || puksDiffer
      ? t.credentialsDiffer
      : (pin !== "" && !lengthOk(pin)) || (setsPuk && puk !== "" && !lengthOk(puk))
        ? t.credentialLength
        : null;

  const words = task === "finish" ? (withPuk ? t.key.finish : t.key.finishKey) : t.key[task];
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
            <div className="flex flex-col gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2.5 text-sm">
              {/* What is lost is said in red, down to the last of it, that
                  it cannot be undone. What is asked for comes after, and
                  is not red. */}
              <div className="flex flex-col gap-1.5">
                {device.ca && (
                  <p className="flex items-start gap-2 text-destructive">
                    <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                    <span>
                      {t.keyHolds(t.roleInText[device.ca.role], commonName(device.ca.subject))}{" "}
                      {t.destroyed}
                      {workspaceRole && ` ${t.key.reset.ofWorkspace[workspaceRole]}`}
                      {device.otherSlots.length === 0 && ` ${t.cannotBeUndone}`}
                    </span>
                  </p>
                )}
                {device.otherSlots.length > 0 && (
                  <p className="text-destructive">
                    {t.key.reset.otherSlots(device.otherSlots)} {t.cannotBeUndone}
                  </p>
                )}
                {!device.ca && device.otherSlots.length === 0 && (
                  <p className="text-destructive">{t.cannotBeUndone}</p>
                )}
              </div>
              {/* A whole sentence stands over this field, not a word or
                  two, and wants more room above it than a label does. */}
              <div className="flex flex-col gap-2.5">
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
            </div>
          )}

          {task !== "reset" && (
            <div className="grid grid-cols-2 gap-3">
              {(task === "change" || task === "finish") && (
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
              {task !== "finish" && (
                <>
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
                </>
              )}
              {setsPuk && (
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

          {/* Nothing to say where only the management key is replaced:
              the one field there is the PIN the key has.

              What is amiss takes the place of the hint without taking its
              room: the two lie on top of each other, so the form keeps
              its height while one types. */}
          {task !== "reset" && (task !== "finish" || withPuk) && (
            <p className="grid text-xs text-muted-foreground">
              <span className={cn("col-start-1 row-start-1", amiss && "invisible")}>
                {task === "protect"
                  ? t.newCredentialsHint
                  : task === "finish"
                    ? t.key.newPukHint
                    : t.key.newPinHint}
              </span>
              {amiss && <span className="col-start-1 row-start-1 text-destructive">{amiss}</span>}
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
