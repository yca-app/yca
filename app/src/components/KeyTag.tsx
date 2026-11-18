import { t } from "@/lib/text";
import { cn } from "@/lib/utils";

/**
 * The serial number of a YubiKey, set apart as a tag that says what the
 * number is.
 *
 * A YubiKey is told from the others by the number printed on it, so the
 * number turns up wherever a key is named, often right above a PIN field.
 * Bare, it could be taken for something to type in there by someone who
 * has just unpacked their first YubiKey.
 */
export function KeyTag({ serial, className }: { serial: number; className?: string }) {
  return (
    <span
      title={t.serialAbout}
      className={cn(
        "inline-flex items-baseline gap-1 rounded-md border bg-muted/50 px-1.5 py-px text-xs leading-[16px] font-normal whitespace-nowrap text-foreground tabular-nums",
        className,
      )}
    >
      <span className="font-medium tracking-wide text-muted-foreground">{t.serialShort}</span>
      {serial}
    </span>
  );
}

/** A YubiKey named by its serial number: the word, then the tag. */
export function KeyName({ serial, className }: { serial: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-baseline gap-1.5", className)}>
      {t.yubikey}
      <KeyTag serial={serial} />
    </span>
  );
}
