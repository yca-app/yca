import { useEffect, useRef, useState } from "react";
import { Bot, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Pki } from "@/lib/api";
import { t } from "@/lib/text";

/** Something that cannot be undone, and so is asked about first. */
export interface Confirmation {
  title: string;
  /** What it is done to: the names of a certificate, the name of a CA. */
  subject: string;
  /** What it means, in a sentence or two. */
  body: string;
  /** The word on the button that does it. */
  confirm: string;
  /** Does it, and resolves to the workspace as it is afterwards. */
  run: () => Promise<Pki>;
  /** The program that asks for it on the person's behalf, if one does,
   *  and the id of its request. */
  from?: string;
  requestId?: string;
  /** Called once it is done, or once the question is put away undone. */
  onSettled?: (done: boolean) => void;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Kept while the dialog fades out, so its words do not change. */
  asked: Confirmation | null;
  /** Called with the workspace as it is afterwards. */
  onDone: (pki: Pki) => void;
}

/**
 * Asks before something that cannot be undone and needs no YubiKey:
 * revoking a certificate, deleting one from the list, revoking an issuing
 * CA that was replaced.
 */
export function ConfirmDialog({ open, onOpenChange, asked, onDone }: Props) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Whoever asked is told how it ended, once.
  const settled = useRef(false);
  useEffect(() => {
    if (!open) return;
    setError(null);
    settled.current = false;
  }, [open, asked]);
  const settle = (done: boolean) => {
    if (settled.current) return;
    settled.current = true;
    asked?.onSettled?.(done);
  };
  const close = () => {
    settle(false);
    onOpenChange(false);
  };

  async function confirm() {
    if (!asked) return;
    setBusy(true);
    try {
      onDone(await asked.run());
      settle(true);
      onOpenChange(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      {/* A click beside the dialog is not an answer. It is easily made by
          accident, as when bringing the window to the front, and a program
          that asked would be told that the person said no. */}
      {/* Nor is a key pressed without looking. The dialog itself takes the
          keyboard, not one of its buttons: Return and Space then answer
          nothing, where they would have pressed Cancel for a person who
          meant yes, or the red button for one who was typing elsewhere
          when a program's question came up. */}
      <DialogContent
        className="sm:max-w-[28rem]"
        onInteractOutside={(event) => event.preventDefault()}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          (event.currentTarget as HTMLElement | null)?.focus();
        }}
      >
        <DialogHeader>
          <DialogTitle>{asked?.title}</DialogTitle>
          <DialogDescription>{asked?.subject}</DialogDescription>
        </DialogHeader>
        {asked?.from && (
          <p className="flex items-start gap-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
            <Bot className="mt-0.5 size-4 shrink-0 text-primary" />
            <span>
              <span className="font-medium">{t.agent.asks(asked.from)}</span> {t.agent.checkDelete}
            </span>
          </p>
        )}
        <p className="text-sm text-muted-foreground">{asked?.body}</p>
        {error && (
          <p className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" className="mr-auto" onClick={close}>
            {t.cancel}
          </Button>
          <Button variant="destructive" disabled={busy} onClick={() => void confirm()}>
            {asked?.confirm}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
