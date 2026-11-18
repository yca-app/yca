import { useId, useState } from "react";
import { Eye, EyeOff } from "lucide-react";

import { KeyTag } from "@/components/KeyTag";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { t } from "@/lib/text";
import { cn } from "@/lib/utils";

/**
 * A field for a PIN, a PUK or a password. What is typed stays hidden
 * unless the eye is clicked, and is never offered to a password manager.
 *
 * `className` sizes the field as a whole; `inputClassName` goes to the
 * input inside it.
 */
export function SecretInput({
  className,
  inputClassName,
  ...props
}: Omit<React.ComponentProps<typeof Input>, "type"> & { inputClassName?: string }) {
  const [shown, setShown] = useState(false);
  return (
    <div className={cn("relative", className)}>
      <Input
        autoComplete="off"
        {...props}
        type={shown ? "text" : "password"}
        className={cn("pr-9", inputClassName)}
      />
      <button
        type="button"
        // Out of the way of Tab, which goes from one field to the next.
        tabIndex={-1}
        aria-label={shown ? t.hideSecret : t.showSecret}
        aria-pressed={shown}
        onClick={() => setShown(!shown)}
        className="absolute inset-y-0 right-0 flex w-9 items-center justify-center rounded-r-md text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        {shown ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </button>
    </div>
  );
}

/** A labelled field for a PIN or a PUK. */
export function Secret({
  label,
  serial,
  hint,
  value,
  onChange,
  invalid,
  autoFocus,
  fieldClassName,
}: {
  label: string;
  /** The YubiKey whose PIN this is; its serial number follows the label
   *  as a tag, so that it is not taken for what to type. */
  serial?: number;
  /** Said under the field: whose PIN this is, where that needs saying. */
  hint?: string;
  /** Sizes the field itself; the hint under it may run on past it. */
  fieldClassName?: string;
  value: string;
  onChange: (value: string) => void;
  invalid?: boolean;
  autoFocus?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>
        {label}
        {serial !== undefined && <KeyTag serial={serial} />}
      </Label>
      <SecretInput
        id={id}
        maxLength={8}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-invalid={invalid}
        autoFocus={autoFocus}
        className={fieldClassName}
        inputClassName="tracking-widest"
      />
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
