import { useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronRight,
  CornerDownRight,
  Ellipsis,
  Folder,
} from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Certificate } from "@/lib/api";
import { profileIcon } from "@/lib/profiles";
import { formatDate, relativeDays, t } from "@/lib/text";
import { cn } from "@/lib/utils";

/** What the list can be put in order by. */
export type SortKey = "name" | "kind" | "status" | "expires";
/** The order the list is in; without one it is newest first. */
export interface Sort {
  by: SortKey;
  descending: boolean;
}

/** The background of a row that stands under the heading of a group. */
const sunken = "bg-foreground/4 hover:bg-foreground/8 dark:bg-black/30 dark:hover:bg-black/10";

/** What the rows of a certificate can ask for. */
interface RowActions {
  /** Point out the certificates the root CA signed itself. Worth saying
   *  only where an issuing CA signs the others. */
  markRootSigned: boolean;
  /** Issue the certificate again for the same key and names, for more time. */
  onRenew: (certificate: Certificate) => void;
  /** Issue it again for the same key under other names. */
  onChangeNames: (certificate: Certificate) => void;
  onRevoke: (certificate: Certificate) => void;
  /** Take it off the list, and its files out of the workspace. */
  onDelete: (certificate: Certificate) => void;
  /** Show the certificate's folder in Finder. */
  onShow: (certificate: Certificate) => void;
  /** Sort it into a group, or take it out of its group. */
  onMove: (certificate: Certificate) => void;
  /** Write its files again, in the form another upload form asks for. */
  onRepackage: (certificate: Certificate) => void;
}

/**
 * The register: one row per certificate, newest first unless a column's
 * heading was clicked.
 *
 * The list is a card set into the page rather than lines running from one
 * edge of the window to the other. It is as tall as its rows; once there
 * are more than fit, it scrolls inside itself and the headings stay put.
 *
 * Rows are picked only while the person is moving certificates between
 * groups: then each has a box, a click ticks it or clears it, and with
 * Shift everything up to it is ticked. At any other time a click on a
 * row does nothing.
 */
export function CertificateTable({
  certificates,
  sections,
  picking,
  sort,
  onSort,
  selected,
  onSelect,
  ...actions
}: {
  /** The certificates to show, in their order. */
  certificates: Certificate[];
  /** Show them under the headings of their groups. */
  sections: boolean;
  /** Whether rows are being picked, to be moved together. */
  picking: boolean;
  sort: Sort | null;
  onSort: (by: SortKey) => void;
  /** Serial numbers of the rows that are picked. */
  selected: ReadonlySet<string>;
  onSelect: (selected: Set<string>) => void;
} & RowActions) {
  // The groups that are folded up. A group nobody has touched is open.
  const [folded, setFolded] = useState<ReadonlySet<string>>(new Set());
  // The row a range picked with Shift starts from.
  const anchor = useRef<string | null>(null);

  // The groups by name, and whatever is in none of them at the end.
  const parts = useMemo(() => {
    if (!sections) return [{ key: null, name: null, rows: certificates }];
    const byGroup = new Map<string, Certificate[]>();
    const loose: Certificate[] = [];
    for (const certificate of certificates) {
      if (certificate.group === null) loose.push(certificate);
      else byGroup.set(certificate.group, [...(byGroup.get(certificate.group) ?? []), certificate]);
    }
    const named = [...byGroup.entries()]
      .sort(([a], [b]) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true }))
      .map(([name, rows]) => ({ key: `group:${name}`, name, rows }));
    return loose.length > 0 ? [...named, { key: "none", name: t.group.none, rows: loose }] : named;
  }, [certificates, sections]);
  // The rows as they stand on the screen, for a range to run along.
  const visible = parts
    .filter((part) => part.key === null || !folded.has(part.key))
    .flatMap((part) => part.rows.map((certificate) => certificate.serial));

  const pick = (serial: string, event: React.MouseEvent) => {
    if (!picking) return;
    // A click on the row's menu, or in it, is not a click on the row.
    if ((event.target as HTMLElement).closest("button, [role=menu]")) return;
    const next = new Set(selected);
    const start = anchor.current === null ? -1 : visible.indexOf(anchor.current);
    if (event.shiftKey && start >= 0) {
      const end = visible.indexOf(serial);
      for (const between of visible.slice(Math.min(start, end), Math.max(start, end) + 1)) {
        next.add(between);
      }
    } else {
      anchor.current = serial;
      if (!next.delete(serial)) next.add(serial);
    }
    onSelect(next);
  };

  // The headings of the columns and of the groups are equally tall; the
  // line under a group's heading counts into its height.
  const tall = "h-10";
  return (
    <div className="min-h-0 overflow-y-auto rounded-lg border bg-card shadow-xs">
      <table className="w-full border-separate border-spacing-0 text-sm">
        <thead className="sticky top-0 z-10 bg-muted">
          <tr className="text-left text-muted-foreground">
            <Heading className={cn("pl-4", tall)} by="name" sort={sort} onSort={onSort}>
              {t.columnName}
            </Heading>
            <Heading className={tall} by="kind" sort={sort} onSort={onSort}>
              {t.columnKind}
            </Heading>
            <Heading className={tall} by="status" sort={sort} onSort={onSort}>
              {t.columnStatus}
            </Heading>
            <Heading className={cn("text-right", tall)} by="expires" sort={sort} onSort={onSort}>
              {t.columnExpires}
            </Heading>
            <th className={cn("w-10 border-b pr-2 pl-0 font-medium", tall)}>
              <span className="sr-only">{t.actions}</span>
            </th>
          </tr>
        </thead>
        {/* The card's own border closes the list; the last row needs no line. */}
        <tbody className="[&_tr:last-child_td]:border-b-0">
          {parts.map((part) => {
            const open = part.key === null || !folded.has(part.key);
            return [
              part.key !== null && (
                <tr key={part.key}>
                  {/* The heading keeps the colour of the card and the rows
                      under it sink a little: that sets it apart without a
                      band whose edges run into the lines between rows. */}
                  <td colSpan={5} className="border-b bg-card p-0">
                    <button
                      type="button"
                      aria-expanded={open}
                      aria-label={t.group.fold(part.name ?? "")}
                      onClick={() => {
                        const next = new Set(folded);
                        if (!next.delete(part.key)) next.add(part.key);
                        setFolded(next);
                      }}
                      className={cn(
                        "flex w-full items-center gap-2 px-3 text-left font-semibold outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:ring-inset",
                        "h-[calc(2.5rem-1px)] text-sm hover:bg-muted/60",
                      )}
                    >
                      <ChevronRight
                        className={cn(
                          "size-4 text-muted-foreground transition-transform",
                          open && "rotate-90",
                        )}
                      />
                      <Folder className="size-4 text-muted-foreground" strokeWidth={1.75} />
                      <span className={cn("truncate", part.key === "none" && "font-normal")}>
                        {part.name}
                      </span>
                      <span className="text-xs font-normal text-muted-foreground tabular-nums">
                        {part.rows.length}
                      </span>
                    </button>
                  </td>
                </tr>
              ),
              open &&
                part.rows.map((certificate) => (
                  <Row
                    key={certificate.serial}
                    certificate={certificate}
                    picking={picking}
                    picked={selected.has(certificate.serial)}
                    // Without headings there is nothing to tell the rows from.
                    tone={part.key === null ? "hover:bg-muted/50" : sunken}
                    onPick={(event) => pick(certificate.serial, event)}
                    {...actions}
                  />
                )),
            ];
          })}
        </tbody>
      </table>
    </div>
  );
}

/** A column's heading. A click puts the list in that column's order, a
 *  second one turns it round, a third leaves it as it was issued. */
function Heading({
  children,
  className,
  by,
  sort,
  onSort,
}: {
  children: string;
  className?: string;
  by: SortKey;
  sort: Sort | null;
  onSort: (by: SortKey) => void;
}) {
  const active = sort?.by === by;
  const Arrow = sort?.descending ? ArrowDown : ArrowUp;
  return (
    <th
      className={cn("border-b px-3 font-medium", className)}
      aria-sort={active ? (sort.descending ? "descending" : "ascending") : undefined}
    >
      <button
        type="button"
        title={t.sortBy(children)}
        onClick={() => onSort(by)}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50",
          active && "text-foreground",
        )}
      >
        {children}
        {active && <Arrow className="size-3" />}
      </button>
    </th>
  );
}

function Row({
  certificate,
  picking,
  picked,
  tone,
  onPick,
  markRootSigned,
  onRenew,
  onChangeNames,
  onRevoke,
  onDelete,
  onShow,
  onMove,
  onRepackage,
}: {
  certificate: Certificate;
  /** Whether rows are being picked, and so whether this one has a box. */
  picking: boolean;
  /** Whether the row is among those picked. */
  picked: boolean;
  /** The row's background while it is not picked. */
  tone: string;
  onPick: (event: React.MouseEvent) => void;
} & RowActions) {
  const [first, ...rest] = certificate.names;
  const Icon = profileIcon[certificate.profile];
  // A server or gateway goes by host names and addresses, a client by a
  // name or an e-mail address.
  const server = certificate.profile === "tls-server" || certificate.profile === "ipsec-gateway";
  const faded = certificate.status === "expired" || certificate.status === "revoked";
  const relative = relativeDays(certificate.notAfter);
  const fromRoot = markRootSigned && certificate.issuedBy === "root";
  // Revoked itself, as opposed to along with its issuing CA: then whoever
  // holds its key is the reason, and it is not issued again.
  const revokedItself = certificate.revokedAt !== null;
  // Taken down by the revocation of its issuing CA and by nothing else,
  // so a new certificate from the new CA puts it right.
  const needsRenewing =
    certificate.issuer === "revoked" && !revokedItself && certificate.status !== "expired";
  // What is worth knowing about where it came from.
  const notes = [
    certificate.replaces && t.replacesOther,
    fromRoot && t.signedByRoot,
    certificate.issuer !== "current" && (needsRenewing ? t.fromRevokedCa : t.fromReplacedCa),
  ].filter(Boolean);

  return (
    // A double click goes where the row's files are, as it would in
    // Finder. While rows are being picked, a click ticks the row instead.
    <tr
      aria-selected={picking ? picked : undefined}
      // Picked rows take the tint the app has for what is chosen; grey
      // would be lost among the headings of the groups.
      className={cn("group", picking && "cursor-pointer", picked ? "bg-primary/10" : tone)}
      onClick={onPick}
      // With Shift held, the click is to pick rows and not to mark text.
      onMouseDown={(event) => picking && event.shiftKey && event.preventDefault()}
      onDoubleClick={(event) => {
        if (picking) return;
        if ((event.target as HTMLElement).closest("button, [role=menu]")) return;
        if (certificate.location) onShow(certificate);
      }}
    >
      <td className="border-b py-2.5 pr-3 pl-4">
        <div className="flex items-center gap-3">
          {picking && (
            <span
              aria-hidden
              className={cn(
                "flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-colors",
                picked
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-muted-foreground/50 bg-background dark:bg-input/30",
              )}
            >
              {picked && <Check className="size-[10px]" strokeWidth={3} />}
            </span>
          )}
          <div className="min-w-0">
            <div
              className={cn(
                "font-medium",
                // Text is for marking and copying, unless clicks tick rows.
                !picking && "selectable",
                faded && "text-muted-foreground",
              )}
            >
              {first}
              {rest.length > 0 && (
                <span className="ml-2 font-normal text-muted-foreground" title={rest.join(", ")}>
                  {rest.length === 1 ? rest[0] : t.more(rest.length)}
                </span>
              )}
            </div>
            {notes.length > 0 && (
              <div className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
                <CornerDownRight className="size-3" />
                {notes.join(" · ")}
              </div>
            )}
          </div>
        </div>
      </td>
      {/* Blocks, not inline boxes, in this cell and the next: an inline
          box sits on the text's baseline and makes the line, and with it
          the row, a fraction of a pixel taller than the text. */}
      <td className="border-b px-3 py-2.5 whitespace-nowrap text-muted-foreground">
        <span className="flex items-center gap-2">
          <Icon className="size-4" strokeWidth={1.75} />
          {t.profile[certificate.profile]}
        </span>
      </td>
      <td className="border-b px-3 py-2.5 whitespace-nowrap">
        <div className="flex">
          <StatusBadge status={certificate.status} />
        </div>
      </td>
      <td className="border-b py-2.5 pr-3 pl-3 text-right whitespace-nowrap tabular-nums">
        <span className={cn(faded && "text-muted-foreground")}>
          {formatDate(certificate.notAfter)}
        </span>
        {relative && certificate.status !== "revoked" && (
          <div className="text-xs text-muted-foreground">{relative}</div>
        )}
      </td>
      <td className="border-b py-1 pr-2 pl-0 text-right">
        {/* Not modal: a dialog opens from this menu, and the two must not
            fight over who holds the focus. */}
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="size-7 text-muted-foreground"
              aria-label={t.actions}
            >
              <Ellipsis />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-72">
            <DropdownMenuItem
              disabled={certificate.location === null}
              onSelect={() => onShow(certificate)}
            >
              {t.showInFinder}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => onMove(certificate)}>{t.group.move}</DropdownMenuItem>
            <DropdownMenuItem onSelect={() => onRepackage(certificate)}>
              {t.repack.menu}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {/* A revoked certificate is not issued again: whoever held its
                key is the reason it was revoked. */}
            <DropdownMenuItem disabled={revokedItself} onSelect={() => onRenew(certificate)}>
              {t.renew}
            </DropdownMenuItem>
            <DropdownMenuItem disabled={revokedItself} onSelect={() => onChangeNames(certificate)}>
              {server ? t.changeNames.server : t.changeNames.client}
            </DropdownMenuItem>
            <DropdownMenuItem
              variant="destructive"
              // With the key of its issuing CA gone, no list can name it.
              disabled={
                certificate.status === "revoked" ||
                certificate.status === "expired" ||
                certificate.issuer !== "current"
              }
              onSelect={() => onRevoke(certificate)}
            >
              {t.revoke}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onSelect={() => onDelete(certificate)}>
              {t.delete}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </td>
    </tr>
  );
}
