import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowRight, Check, CircleArrowUp, LoaderCircle, TriangleAlert, X } from "lucide-react";

import { tagLook } from "@/components/KeyTag";
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
import {
  api,
  UPDATE_CANCELLED,
  type NewVersion,
  type UpdateProgress,
  type UpdateStatus,
} from "@/lib/api";
import { formatDate, t } from "@/lib/text";
import { cn } from "@/lib/utils";

// What the window keeps between launches, in its own storage.
// "off" once the person has said that the app is not to look by itself.
const AUTO = "yca.updates.auto";
// When the app last looked by itself.
const LAST_LOOK = "yca.updates.lastLook";
// The newer version it found last, with what its release says, so that
// the line about it and the dialog are there again after a restart without
// asking again.
const KNOWN = "yca.updates.known";
// The version that is being installed, so that the app can say after its
// restart that it worked.
const INSTALLING = "yca.updates.installing";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
// How long the dialog says that it is looking, at the least. An answer
// that is there at once would otherwise flash past while the dialog is
// still coming up.
const LEAST = 600;

const pause = (time: number) => new Promise<void>((done) => window.setTimeout(done, time));

/** The newer version that was kept when the app last ran, if what is kept
 *  reads as one. */
function kept(): NewVersion | null {
  try {
    const record: unknown = JSON.parse(localStorage.getItem(KNOWN) ?? "null");
    if (typeof record !== "object" || record === null) return null;
    const { version, notes, date } = record as Record<string, unknown>;
    if (typeof version !== "string") return null;
    return {
      version,
      notes: typeof notes === "string" ? notes : null,
      date: typeof date === "string" ? date : null,
    };
  } catch {
    return null;
  }
}

/** Whether version `a` is newer than version `b`, going by their numbers. */
function newer(a: string, b: string): boolean {
  const numbers = (version: string) =>
    version.split(/[.+-]/).map((part) => Number.parseInt(part, 10) || 0);
  const [left, right] = [numbers(a), numbers(b)];
  for (let at = 0; at < Math.max(left.length, right.length); at += 1) {
    const [x, y] = [left[at] ?? 0, right[at] ?? 0];
    if (x !== y) return x > y;
  }
  return false;
}

/** A version number, set apart as a tag of the same make as the serial
 *  number of a YubiKey. Beside a newer one, the one that is left behind is
 *  the paler of the two. */
function Version({ number, left }: { number: string; left?: boolean }) {
  return <span className={cn(tagLook, left && "text-muted-foreground")}>{number}</span>;
}

/** What an update comes down to: the version that is running, an arrow,
 *  and the version that is offered. */
function Versions({ from, to }: { from: string; to: string }) {
  return (
    <span
      role="img"
      aria-label={t.update.versions(from, to)}
      className="inline-flex shrink-0 items-center gap-1.5"
    >
      <Version number={from} left />
      <ArrowRight className="size-3.5 text-muted-foreground" />
      <Version number={to} />
    </span>
  );
}

/**
 * What changed in a release, as its entry in the changelog says it: a few
 * headings, and under each a list whose items may begin with a phrase in
 * bold. That much of Markdown is read, and the rest is shown as it is
 * written. The text comes from the internet and is never taken for
 * anything but text.
 */
function Notes({ text }: { text: string }) {
  const plain = (words: string) => words.replace(/\*\*|`/g, "");
  type Block = { heading: string } | { items: { lead: string; rest: string }[] } | { text: string };
  const blocks: Block[] = [];
  for (const line of text.split("\n").map((each) => each.trim())) {
    if (line === "") continue;
    const heading = line.match(/^#{1,6}\s+(.*)$/);
    const item = line.match(/^[-*•]\s+(.*)$/);
    if (heading) {
      blocks.push({ heading: plain(heading[1]) });
    } else if (item) {
      const lead = item[1].match(/^\*\*(.+?)\*\*\s*(.*)$/);
      const entry = lead
        ? { lead: plain(lead[1]), rest: plain(lead[2]) }
        : { lead: "", rest: plain(item[1]) };
      const last = blocks[blocks.length - 1];
      if (last && "items" in last) last.items.push(entry);
      else blocks.push({ items: [entry] });
    } else {
      blocks.push({ text: plain(line) });
    }
  }
  return (
    <div className="selectable flex max-h-56 flex-col gap-2 overflow-y-auto rounded-lg border bg-muted/40 px-3 py-2.5">
      {blocks.map((block, at) =>
        "heading" in block ? (
          <p key={at} className="text-xs font-medium text-muted-foreground not-first:mt-1">
            {block.heading}
          </p>
        ) : "items" in block ? (
          <ul key={at} className="flex flex-col gap-1.5">
            {block.items.map((entry, index) => (
              <li key={index} className="flex items-start gap-2.5">
                <span
                  aria-hidden
                  className="mt-2 size-1 shrink-0 rounded-full bg-muted-foreground/70"
                />
                <span>
                  {entry.lead && <span className="font-medium">{entry.lead} </span>}
                  {entry.rest}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p key={at}>{block.text}</p>
        ),
      )}
    </div>
  );
}

// Where the dialog stands.
type Phase =
  | "checking"
  // Nothing newer was found.
  | "current"
  | "found"
  | "downloading"
  // All of it is here and checked, and is being put in place.
  | "installing"
  // The question whether there is a newer version got no answer.
  | "no-answer"
  | "not-installed";

/**
 * A newer version of the app itself: looking for one, saying so, and
 * installing it when the person says to.
 *
 * Only a released app does any of this. One built from source has no
 * updater, and then there is neither a line nor a dialog, and nothing is
 * asked of anybody.
 *
 * The app looks by itself when it starts, at most once a day, unless that
 * was turned off; all that comes of it is a line in the window. Nothing is
 * downloaded before the person has opened the dialog and said so, and the
 * dialog never comes up over something they are in the middle of.
 *
 * The dialog comes up as it will stay. Opened from the line in the window,
 * it shows the version the app knows of, at once and without asking; that
 * this is still the one that is out is asked when it is to be installed.
 * Opened from the menu, it asks first and says that it does.
 */
export function useUpdates({
  occupied,
  makeRoom,
}: {
  /** The person is in the middle of something else in the window. */
  occupied: boolean;
  /** Puts away a result that was only standing there to be read. */
  makeRoom: () => void;
}): {
  /** Whether the dialog is up. */
  open: boolean;
  /** The line for the window, if there is something to say. */
  notice: React.ReactNode;
  dialog: React.ReactNode;
} {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  // The newer version the app knows of: what the line in the window and
  // the dialog are about.
  const [found, setFound] = useState<NewVersion | null>(null);
  // The version that "Not now" was said to, for as long as the app runs.
  const [putOff, setPutOff] = useState<string | null>(null);
  // The version the app has just been updated to.
  const [updated, setUpdated] = useState<string | null>(null);
  const [auto, setAuto] = useState(() => localStorage.getItem(AUTO) !== "off");

  const [open, setOpen] = useState(false);
  const [phase, setPhase] = useState<Phase>("checking");
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The version that is being installed, as it was when the person said
  // so. What the dialog shows while it downloads is this, whatever a look
  // that comes back late has to say.
  const [chosen, setChosen] = useState<NewVersion | null>(null);

  // What the app knows about itself, asked once.
  useEffect(() => {
    let gone = false;
    void api
      .updateStatus()
      .then((now) => {
        if (gone) return;
        setStatus(now);
        // Started anew by an update: that it worked is said once.
        const installing = localStorage.getItem(INSTALLING);
        localStorage.removeItem(INSTALLING);
        if (installing === now.version) setUpdated(now.version);
        // A newer version found before is still news; one that is not
        // newer any more is forgotten.
        const before = kept();
        if (before && newer(before.version, now.version)) setFound(before);
        else localStorage.removeItem(KNOWN);
      })
      .catch(() => {});
    return () => {
      gone = true;
    };
  }, []);
  const available = status?.available ?? false;

  const learn = useCallback((version: NewVersion | null) => {
    setFound(version);
    if (version) localStorage.setItem(KNOWN, JSON.stringify(version));
    else localStorage.removeItem(KNOWN);
  }, []);

  // Looks by itself: when the app starts, and while it stays open, once a
  // day. That it could not ask is nothing to say; the next day asks again.
  useEffect(() => {
    if (!available || !auto) return;
    const look = async () => {
      if (Date.now() - Number(localStorage.getItem(LAST_LOOK) ?? 0) < DAY) return;
      localStorage.setItem(LAST_LOOK, String(Date.now()));
      try {
        learn(await api.checkForUpdate());
      } catch {
        // Offline, or the place that is asked is.
      }
    };
    void look();
    const timer = window.setInterval(() => void look(), HOUR);
    return () => window.clearInterval(timer);
  }, [available, auto, learn]);

  // Counts what the dialog was last told to do, so that an answer which
  // comes after the dialog has gone on to something else does not take it
  // back.
  const turn = useRef(0);

  // Looks because the person asked: the dialog says that it is looking, and
  // then what came of it.
  const look = useCallback(async () => {
    const mine = (turn.current += 1);
    setPhase("checking");
    setError(null);
    setProgress(null);
    const shown = pause(LEAST);
    try {
      const version = await api.checkForUpdate();
      localStorage.setItem(LAST_LOOK, String(Date.now()));
      await shown;
      learn(version);
      if (turn.current === mine) setPhase(version ? "found" : "current");
    } catch (reason) {
      await shown;
      if (turn.current !== mine) return;
      setError(String(reason));
      setPhase("no-answer");
    }
  }, [learn]);

  // Kept in refs, as the listener below is set up once and has to meet the
  // window as it is by then.
  const room = useRef(makeRoom);
  room.current = makeRoom;
  // Brings the dialog up. `asking` when the person wants the app to look;
  // otherwise it shows the version the app already knows of, if it does.
  const show = useCallback(
    (asking: boolean) => {
      room.current();
      setOpen(true);
      if (asking || !found) {
        void look();
        return;
      }
      turn.current += 1;
      setError(null);
      setProgress(null);
      setPhase("found");
    },
    [found, look],
  );
  const now = useRef({ occupied, open, show });
  now.current = { occupied, open, show };

  // "Check for Updates…" in the menu. Chosen while the person is in the
  // middle of something, it waits until they are done.
  const wanted = useRef(false);
  useEffect(() => {
    let stop: (() => void) | undefined;
    let gone = false;
    void api
      .onCheckForUpdates(() => {
        if (now.current.open) return;
        if (now.current.occupied) wanted.current = true;
        else now.current.show(true);
      })
      .then((stopListening) => {
        if (gone) stopListening();
        else stop = stopListening;
      });
    return () => {
      gone = true;
      stop?.();
    };
  }, []);
  useEffect(() => {
    if (occupied || open || !wanted.current) return;
    wanted.current = false;
    show(true);
  }, [occupied, open, show]);

  const install = useCallback(async () => {
    if (!found) return;
    const shown = found.version;
    turn.current += 1;
    setChosen(found);
    setPhase("downloading");
    setProgress(null);
    setError(null);
    try {
      // Asked afresh at this moment, as what the dialog shows may be what
      // the app found hours ago: the app installs what is out now, and only
      // if that is the version the person was shown. If another one is out
      // by now, or none, the dialog shows that and installs nothing.
      const latest = await api.checkForUpdate();
      localStorage.setItem(LAST_LOOK, String(Date.now()));
      if (latest?.version !== shown) {
        learn(latest);
        setPhase(latest ? "found" : "current");
        return;
      }
      // Read after the restart, to say that it worked.
      localStorage.setItem(INSTALLING, shown);
      await api.installUpdate(shown, (state) => {
        setProgress(state);
        if (state.installing) setPhase("installing");
      });
    } catch (reason) {
      localStorage.removeItem(INSTALLING);
      // Given up by the person: back to where they said to install it.
      if (reason === UPDATE_CANCELLED) {
        setPhase("found");
        return;
      }
      setError(String(reason));
      setPhase("not-installed");
    }
  }, [found, learn]);

  const chooseAuto = (on: boolean) => {
    setAuto(on);
    if (on) localStorage.removeItem(AUTO);
    else localStorage.setItem(AUTO, "off");
  };

  if (!status?.available) return { open: false, notice: null, dialog: null };

  // While it is downloaded and put in place the dialog stays. A download
  // can be given up with its own button; what is put in place is seen
  // through.
  const working = phase === "downloading" || phase === "installing";
  // What the dialog is about: while it works, the version that was chosen.
  const subject = working ? (chosen ?? found) : found;
  const close = () => {
    if (!working) setOpen(false);
  };
  const percent =
    progress?.total && progress.total > 0
      ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100))
      : null;

  const notice = updated ? (
    <div className="flex shrink-0 items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-left">
      <Check className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
      <p className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1">
        {t.update.updated}
        <Version number={updated} />
      </p>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label={t.update.dismiss}
        title={t.update.dismiss}
        onClick={() => setUpdated(null)}
      >
        <X />
      </Button>
    </div>
  ) : found && found.version !== putOff ? (
    // It stays where it is while the dialog is up, so that the window behind
    // the dialog does not move when the dialog comes and goes.
    <div className="flex shrink-0 items-center gap-3 rounded-lg border border-primary/25 bg-primary/5 px-3 py-2 text-left">
      <CircleArrowUp className="size-4 shrink-0 text-primary" />
      <p className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2.5 gap-y-1">
        {t.update.available}
        <Versions from={status.version} to={found.version} />
      </p>
      <Button variant="outline" size="sm" onClick={() => show(false)}>
        {t.update.open}
      </Button>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label={t.update.notNow}
        title={t.update.notNow}
        onClick={() => setPutOff(found.version)}
      >
        <X />
      </Button>
    </div>
  ) : null;

  const dialog = (
    <Dialog open={open} onOpenChange={(next) => (next ? setOpen(true) : close())}>
      {/* A click beside the dialog is not an answer, and a key pressed
          without looking installs nothing: the dialog itself takes the
          keyboard, not one of its buttons.

          It is not centred as the other dialogs are, as its height changes
          with what it has to say, and a centred one would then move under
          the pointer. Its top stays where the top of the tallest one is
          when that one is centred, and what changes, changes below. */}
      <DialogContent
        className="top-[max(11px,calc(50%-249px))] translate-y-0 sm:max-w-[calc(30rem+6px)]"
        showCloseButton={!working}
        onInteractOutside={(event) => event.preventDefault()}
        onEscapeKeyDown={(event) => {
          if (working) event.preventDefault();
        }}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          (event.currentTarget as HTMLElement | null)?.focus();
        }}
      >
        <DialogHeader>
          <DialogTitle>{t.update.title}</DialogTitle>
          {/* As tall with a tag in it as without one, so that the answer
              takes the place of the question and nothing below it moves. */}
          <DialogDescription className="flex min-h-[20px] items-center gap-2">
            {phase === "checking" ? (
              <>
                <LoaderCircle className="size-3.5 shrink-0 animate-spin" />
                {t.update.checking}
              </>
            ) : phase === "current" ? (
              <>
                {t.update.upToDate}
                <Version number={status.version} />
              </>
            ) : phase === "no-answer" ? (
              t.update.couldNotCheck
            ) : (
              t.update.found
            )}
          </DialogDescription>
        </DialogHeader>

        {/* From which version to which, and since when the new one is out:
            there from the moment it is found until it is in place. */}
        {subject && phase !== "checking" && phase !== "current" && phase !== "no-answer" && (
          <div className="flex items-center justify-between gap-3">
            <Versions from={status.version} to={subject.version} />
            {subject.date && (
              <span className="text-xs text-muted-foreground">
                {t.update.released(formatDate(subject.date))}
              </span>
            )}
          </div>
        )}

        {phase === "found" && found && (
          <>
            {found.notes && <Notes text={found.notes} />}
            <p className="text-muted-foreground">{t.update.about}</p>
          </>
        )}

        {working && (
          <div className="flex flex-col gap-2 py-1">
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={phase === "installing" ? 100 : (percent ?? undefined)}
              className="h-1.5 overflow-hidden rounded-full bg-muted"
            >
              <div
                className={
                  phase === "installing" || percent === null
                    ? "h-full w-full animate-pulse bg-primary/60"
                    : "h-full bg-primary transition-[width] duration-200"
                }
                style={
                  phase === "installing" || percent === null ? undefined : { width: `${percent}%` }
                }
              />
            </div>
            <p className="text-muted-foreground">
              {phase === "installing" ? t.update.installing : t.update.downloading(percent)}
            </p>
          </div>
        )}

        {(phase === "no-answer" || phase === "not-installed") && (
          <p className="selectable flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span>
              {phase === "not-installed" && <span className="block">{t.update.couldNotInstall}</span>}
              <span className={phase === "not-installed" ? "block text-xs opacity-80" : undefined}>
                {error}
              </span>
            </span>
          </p>
        )}

        {!working && (
          <label className="flex items-start gap-2.5">
            <Checkbox
              className="mt-0.5"
              checked={auto}
              onCheckedChange={(checked) => chooseAuto(checked === true)}
            />
            <span>
              <span className="block">{t.update.auto}</span>
              <span className="block text-xs text-muted-foreground">{t.update.autoHint}</span>
            </span>
          </label>
        )}

        {/* A download can take a while on a slow line, or never end on a
            broken one: it can be given up. */}
        {phase === "downloading" && (
          <DialogFooter>
            <Button variant="ghost" className="mr-auto" onClick={() => void api.cancelUpdate()}>
              {t.cancel}
            </Button>
          </DialogFooter>
        )}

        {!working && (
          <DialogFooter>
            {phase === "found" ? (
              <>
                <Button variant="ghost" className="mr-auto" onClick={close}>
                  {t.update.later}
                </Button>
                <Button onClick={() => void install()}>{t.update.install}</Button>
              </>
            ) : phase === "no-answer" || phase === "not-installed" ? (
              <>
                <Button variant="ghost" className="mr-auto" onClick={close}>
                  {t.update.close}
                </Button>
                <Button onClick={() => void (phase === "no-answer" ? look() : install())}>
                  {t.update.tryAgain}
                </Button>
              </>
            ) : (
              <Button variant="outline" onClick={close}>
                {t.update.close}
              </Button>
            )}
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );

  return { open, notice, dialog };
}
