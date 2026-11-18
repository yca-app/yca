import type { Files } from "@/lib/api";
import { t } from "@/lib/text";
import { cn } from "@/lib/utils";

/** The look of one choice among a few that each take a line or two. */
export const choiceLook =
  "flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-left transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

/** The mark of such a choice: a ring, filled in when it is the one. */
export function RadioMark({ checked }: { checked: boolean }) {
  return (
    <span
      className={cn(
        // Three pixels down: the middle of a 12 px ring on the middle of
        // the 18 px line of the title beside it.
        "mt-[3px] flex size-3.5 shrink-0 items-center justify-center rounded-full border",
        checked ? "border-primary" : "border-muted-foreground/50",
      )}
    >
      {checked && <span className="size-1.5 rounded-full bg-primary" />}
    </span>
  );
}

/**
 * What the upload form of the device asks for, which decides the files a
 * certificate is handed over as. The choices are told apart by what the
 * person sees on that form, not by what kind of device it is: a field for
 * the certificate and one for the key, a field for each, or one file with
 * a password.
 */
export function FilesChoice({
  value,
  onChange,
  withKey,
  chain,
  current,
}: {
  value: Files;
  onChange: (files: Files) => void;
  /** Whether there is a private key to hand over. Without one, as for a
   *  device that made its own, nothing can go into one file. */
  withKey: boolean;
  /** Whether an intermediate CA comes with the certificate. Where the
   *  root CA signs there is none: the choice with a file for one is then
   *  there to be seen, switched off, and says why. */
  chain: boolean;
  /** The form the files are in now, to say so beside it. */
  current?: Files | null;
}) {
  const offered: Files[] = ["fullchain", "separate", ...(withKey ? (["p12"] as const) : [])];
  // Shown, so that whoever has a form with a field for the intermediate
  // CA finds what they look for and reads why it does not apply here.
  const off = (files: Files) => files === "separate" && !chain;
  // What is chosen, among what can be.
  const chosen = offered.includes(value) && !off(value) ? value : "fullchain";
  const title = (files: Files) =>
    files === "p12" || withKey ? t.files.option[files] : t.files.optionNoKey[files];
  const about = (files: Files) => {
    if (files === "p12") return t.files.about.p12;
    if (!chain) return (withKey ? t.files.aboutNoChain : t.files.aboutNoKeyNoChain)[files];
    return withKey ? t.files.about[files] : t.files.aboutNoKey[files];
  };
  return (
    <div className="flex flex-col gap-1.5" role="radiogroup" aria-label={t.files.title}>
      {offered.map((files) => (
        <button
          key={files}
          type="button"
          role="radio"
          aria-checked={chosen === files}
          disabled={off(files)}
          onClick={() => onChange(files)}
          className={cn(
            choiceLook,
            "disabled:cursor-not-allowed",
            chosen === files ? "border-primary bg-primary/5" : "enabled:hover:bg-muted/60",
          )}
        >
          {/* Switched off, the ring and the title fade; the line that
              says why stays as readable as any other. */}
          <span className={cn("flex", off(files) && "opacity-40")}>
            <RadioMark checked={chosen === files} />
          </span>
          <span className="min-w-0">
            <span className={cn("block", off(files) && "text-muted-foreground/70")}>
              {title(files)}
              {current === files && (
                <span className="ml-2 text-xs text-muted-foreground">{t.files.now}</span>
              )}
            </span>
            <span className="block text-xs text-muted-foreground">{about(files)}</span>
          </span>
        </button>
      ))}
    </div>
  );
}
