import { useRef, useState } from "react";
import { ChevronDown, Folder } from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { t } from "@/lib/text";
import { cn } from "@/lib/utils";

/**
 * Says which group a certificate goes into: none, one of those there are,
 * or a new one, which is made by naming it.
 *
 * Small enough to sit beside a heading, so that sorting a certificate
 * costs the dialog it is in no room.
 */
export function GroupPicker({
  group,
  groups,
  onChange,
  className,
}: {
  /** The chosen group; `null` for none. */
  group: string | null;
  /** The groups the workspace has. */
  groups: string[];
  onChange: (group: string | null) => void;
  className?: string;
}) {
  // Whether a new group is being named, in place of the menu.
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  // The menu gives the focus back to its button as it closes. When the
  // button has just made way for the field, the field is to keep it.
  const startedNaming = useRef(false);

  const commit = () => {
    const tidy = name.trim().replace(/\s+/g, " ");
    // The spelling of a group that is there already wins.
    const known = groups.find((existing) => existing.toLowerCase() === tidy.toLowerCase());
    if (tidy !== "") onChange(known ?? tidy);
    setNaming(false);
    setName("");
  };

  if (naming) {
    return (
      <Input
        autoFocus
        value={name}
        onChange={(event) => setName(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => {
          if (event.key !== "Enter") return;
          // The dialog around it is not what Enter is meant for here.
          event.preventDefault();
          commit();
        }}
        maxLength={60}
        placeholder={t.group.namePlaceholder}
        aria-label={t.group.namePlaceholder}
        className={cn("h-7 w-48", className)}
      />
    );
  }

  // A group that was just named is on offer too, before anything is in it.
  const offered = group === null || groups.includes(group) ? groups : [...groups, group];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`${t.group.label}: ${group ?? t.group.none}`}
          className={cn(
            "flex max-w-56 items-center gap-1.5 rounded-md px-2 py-1 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
            group === null
              ? "text-muted-foreground hover:text-foreground"
              : "bg-secondary text-secondary-foreground",
            className,
          )}
        >
          <Folder className="size-3.5 shrink-0" strokeWidth={1.75} />
          <span className="truncate">{group ?? t.group.none}</span>
          <ChevronDown className="size-3 shrink-0 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="max-h-72 w-56"
        onCloseAutoFocus={(event) => {
          if (!startedNaming.current) return;
          startedNaming.current = false;
          event.preventDefault();
        }}
      >
        <DropdownMenuRadioGroup
          value={group ?? ""}
          onValueChange={(value) => onChange(value === "" ? null : value)}
        >
          <DropdownMenuRadioItem value="">{t.group.none}</DropdownMenuRadioItem>
          {offered.map((existing) => (
            <DropdownMenuRadioItem key={existing} value={existing}>
              <span className="truncate">{existing}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={() => {
            startedNaming.current = true;
            setNaming(true);
          }}
        >
          {t.group.new}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
