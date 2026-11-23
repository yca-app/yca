import { Ellipsis, FolderOpen, RefreshCw, ShieldCheck, TriangleAlert, Usb } from "lucide-react";

import type { KeyTask } from "@/components/KeyDialog";
import { KeyName, KeyTag } from "@/components/KeyTag";
import { PathTail } from "@/components/PathTail";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { holdsCa, type Ca, type CaRole, type Device, type Devices, type Pki } from "@/lib/api";
import type { RetiredCa } from "@/lib/api";
import { commonName, formatDate, t } from "@/lib/text";
import { cn } from "@/lib/utils";

interface Props {
  pki: Pki;
  devices: Devices | null;
  /** Something that went wrong and has not been shown elsewhere. */
  error: string | null;
  onOpenAnother: () => void;
  onRefresh: () => void;
  /** Adds the issuing CA from a connected YubiKey to this workspace. */
  onAdoptIssuing: () => void;
  /** Starts making an issuing CA for this workspace on a second YubiKey. */
  onAddIssuing: () => void;
  /** Starts making an issuing CA to take the place of the one there is. */
  onReplaceIssuing: () => void;
  /** Asks whether to revoke an issuing CA that was replaced. */
  onRevokeReplaced: (ca: RetiredCa) => void;
  /** Starts something to do with a connected YubiKey's own PIN, or its
   *  reset. */
  onKeyTask: (device: Device, task: KeyTask) => void;
  /** Shows how to make a computer or a phone trust this CA. */
  onTrust: () => void;
  /** Leaves this workspace and goes back to the start. */
  onClose: () => void;
}

/** The left column: which CAs the workspace is of and where their YubiKeys are. */
export function Sidebar({
  pki,
  devices,
  error,
  onOpenAnother,
  onRefresh,
  onAdoptIssuing,
  onAddIssuing,
  onReplaceIssuing,
  onRevokeReplaced,
  onKeyTask,
  onTrust,
  onClose,
}: Props) {
  const connected = devices?.usable ?? [];
  // An issuing CA of this PKI's root that is plugged in while the PKI has
  // none yet: the one to offer.
  const candidate = pki.issuing
    ? undefined
    : connected.find((device) => device.ca?.role === "issuing" && device.ca.signedByRoot);
  const known = new Set([pki.root.yubikey, pki.issuing?.yubikey, candidate?.serial]);

  const rootCard = (
    <CaCard
      role="root"
      ca={pki.root}
      device={connected.find((device) => device.serial === pki.root.yubikey)}
      known={devices !== null}
      // A root with an issuing CA under it belongs in the safe; one that
      // is the whole authority is what signs every day.
      everyday={pki.issuing === null}
      onKeyTask={onKeyTask}
      onTrust={onTrust}
    />
  );
  const issuingCard = (
    <CaCard
      role="issuing"
      ca={pki.issuing}
      device={connected.find((device) => device.serial === pki.issuing?.yubikey)}
      known={devices !== null}
      candidate={candidate}
      onAdopt={onAdoptIssuing}
      onAdd={onAddIssuing}
      onReplace={onReplaceIssuing}
      onKeyTask={onKeyTask}
    />
  );
  // A replaced issuing CA is worth a line for as long as a certificate of
  // its could still be accepted.
  const retired = pki.retired.filter((ca) => new Date(ca.notAfter).getTime() > Date.now());
  const strangers = connected.filter((device) => !known.has(device.serial));
  const unusable = devices?.unusable ?? [];

  return (
    <aside className="flex w-[23rem] shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground">
      {/* Room for the window buttons; also where the window is dragged. */}
      <div data-tauri-drag-region className="h-12 shrink-0" />

      {/* One left and one right edge for the whole column: headings, cards
          and the footer all start and end on it. */}
      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto px-5 pb-3">
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              {t.authorities}
            </h2>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  // Pulled out by its own padding, so the icon itself
                  // ends where the cards do.
                  className="-mr-1 size-6 text-muted-foreground"
                  onClick={onRefresh}
                  aria-label={t.refresh}
                >
                  <RefreshCw className="size-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t.refresh}</TooltipContent>
            </Tooltip>
          </div>
          {/* Drawn as the tree it is: the issuing CA is set in, and a branch
              runs out of the root's lower left, down, and into the middle
              of its side. */}
          {rootCard}
          <div className="relative mt-2 pl-6">
            <span
              aria-hidden
              className="absolute -top-2 bottom-1/2 left-2.5 w-3.5 rounded-bl-md border-b border-l border-dashed border-muted-foreground/60"
            />
            {issuingCard}
          </div>
          {/* Below the tree, so its branch still ends at the middle of the card. */}
          {retired.length > 0 && (
            <ul className="mt-2 flex flex-col gap-1.5 pl-6 text-xs text-muted-foreground">
              {retired.map((ca) => (
                <li key={ca.serial} className="flex items-start gap-2 pl-3">
                  <span className="min-w-0 flex-1">
                    <span className="selectable block truncate" title={ca.subject}>
                      {t.replacedCa(commonName(ca.subject))}
                    </span>
                    <span className="block">
                      {ca.revokedAt
                        ? t.replacedCaRevoked(formatDate(ca.revokedAt))
                        : t.replacedCaValid}
                    </span>
                  </span>
                  {!ca.revokedAt && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="-mr-1 h-6 px-2"
                      onClick={() => onRevokeReplaced(ca)}
                    >
                      {t.revokeCa}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        {error && (
          <p className="selectable flex items-start gap-1.5 text-destructive">
            <TriangleAlert className="mt-px size-3.5 shrink-0" />
            {error}
          </p>
        )}

        {(strangers.length > 0 || unusable.length > 0) && (
          <section>
            <h2 className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              {t.otherKeys}
            </h2>
            <ul className="flex flex-col gap-1 text-xs text-muted-foreground">
              {strangers.map((device) => (
                <li key={device.serial}>
                  {/* The icon, the name and the menu share one line and its
                      middle; what the key holds goes under the name. */}
                  <div className="flex items-center gap-2">
                    {/* Green: it is plugged in. */}
                    <Usb className="size-4 shrink-0 text-connected" />
                    <KeyName
                      serial={device.serial}
                      className="min-w-0 flex-1 text-sm font-medium text-sidebar-foreground"
                    />
                    <DropdownMenu modal={false}>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="-mr-1 size-6 shrink-0 text-muted-foreground"
                          aria-label={t.actions}
                        >
                          <Ellipsis className="size-3.5" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-56">
                        <KeyItems device={device} onKeyTask={onKeyTask} />
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                  <p className="pr-6 pl-6">
                    {device.ca
                      ? t.holdsOtherCa(commonName(device.ca.subject))
                      : device.keyWithoutCertificate
                        ? t.holdsLoneKey
                        : device.slotInUse
                          ? t.holdsNotCa
                          : t.holdsNoCa}
                  </p>
                </li>
              ))}
              {unusable.map((reader) => (
                <li key={reader.reader}>
                  <div className="flex items-center gap-2">
                    <Usb className="size-4 shrink-0" />
                    <span className="min-w-0 truncate text-sm font-medium text-sidebar-foreground">
                      {reader.reader}
                    </span>
                  </div>
                  <p className="pl-6">{t.unusableKey}</p>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>

      {/* Two rows: the path gets the whole width of the sidebar, which most
          paths then fit into. */}
      <div className="border-t px-5 py-2">
        <div className="flex items-center gap-2">
          <FolderOpen className="size-3.5 shrink-0 text-muted-foreground" />
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="min-w-0 flex-1 font-medium">{t.workspace}</p>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-72">
              {t.workspaceAbout}
            </TooltipContent>
          </Tooltip>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="h-[23px] px-2">
                {t.switchWorkspace}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" side="top" className="w-64">
              <DropdownMenuItem onSelect={onOpenAnother}>{t.openAnother}</DropdownMenuItem>
              <DropdownMenuItem onSelect={onClose}>{t.startFromKeys}</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="mt-1">
              <PathTail path={pki.path} className="text-xs text-muted-foreground" />
            </div>
          </TooltipTrigger>
          <TooltipContent side="top" className="max-w-72 break-all">
            {pki.path}
          </TooltipContent>
        </Tooltip>
      </div>
    </aside>
  );
}

/** What can be done to a connected YubiKey's own PIN, and its reset. The
 *  same wherever a key has a menu: in the sidebar, and before there is a
 *  workspace, where a key is often reset in order to start one. */
export function KeyItems({
  device,
  onKeyTask,
}: {
  device: Device;
  onKeyTask: (device: Device, task: KeyTask) => void;
}) {
  return (
    <>
      {/* A key with its factory PIN gets a PUK of its own along with it. */}
      <DropdownMenuItem
        onSelect={() => onKeyTask(device, device.factoryPin ? "protect" : "change")}
      >
        {t.key.changePin}
      </DropdownMenuItem>
      <DropdownMenuItem disabled={device.factoryPin} onSelect={() => onKeyTask(device, "unblock")}>
        {t.key.unblockPin}
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem variant="destructive" onSelect={() => onKeyTask(device, "reset")}>
        {t.key.resetKey}
      </DropdownMenuItem>
    </>
  );
}

function CaCard({
  role,
  ca,
  device,
  known,
  everyday,
  candidate,
  onAdopt,
  onAdd,
  onReplace,
  onKeyTask,
  onTrust,
}: {
  role: CaRole;
  ca: Ca | null;
  /** The connected YubiKey with this CA's serial number, if any. */
  device: Device | undefined;
  /** Whether the YubiKeys have been looked at yet. */
  known: boolean;
  /** This root CA signs certificates itself; there is no issuing CA. */
  everyday?: boolean;
  /** A connected YubiKey that holds this CA while the workspace lacks it. */
  candidate?: Device;
  /** Adds the candidate's CA to the workspace. */
  onAdopt?: () => void;
  /** Starts making this CA, where there is none to take over. */
  onAdd?: () => void;
  /** Starts making a CA to take this one's place. */
  onReplace?: () => void;
  /** Starts something to do with the PIN of this CA's YubiKey, or its
   *  reset. */
  onKeyTask: (device: Device, task: KeyTask) => void;
  /** Shows how to make devices trust this CA; the root CA's to offer. */
  onTrust?: () => void;
}) {
  if (!ca) {
    // In the light theme the usual border all but vanishes on the grey of
    // the sidebar once it is dashed, so the outline takes the colour of the
    // line that leads to it.
    return (
      <div className="rounded-lg border border-dashed border-muted-foreground/60 px-3 py-2.5 dark:border-border">
        <p className="text-xs text-muted-foreground">{t.roleInTree[role]}</p>
        <p className="mt-0.5 text-lg font-medium">{t.noIssuing}</p>
        <p className="mt-0.5 text-muted-foreground">{t.noIssuingAbout}</p>
        {candidate?.ca ? (
          <>
            <p className="mt-2 border-t pt-2 text-xs text-muted-foreground">
              {t.issuingFound(commonName(candidate.ca.subject), candidate.serial)}
            </p>
            <Button variant="outline" size="sm" className="mt-2 h-[26px] w-full" onClick={onAdopt}>
              {t.adoptIssuing}
            </Button>
          </>
        ) : (
          onAdd && (
            <Button variant="outline" size="sm" className="mt-2 h-[26px] w-full" onClick={onAdd}>
              {t.addIssuing}
            </Button>
          )
        )}
      </div>
    );
  }

  // The YubiKey with the right serial may still hold something else, or
  // the folder may: the two have to hold the very same certificate.
  const holdsThisCa = holdsCa(device, role, ca);
  const warnings: string[] = [];
  if (device && !holdsThisCa) warnings.push(device.ca ? t.wrongKey : t.key.holdsNothing);
  if (device && holdsThisCa && !device.ca?.keyMatchesCertificate) warnings.push(t.keyMismatch);
  if (holdsThisCa && device?.ca?.generatedOnDevice === false) warnings.push(t.keyImported);
  if (device?.factoryCredentials && !device.factoryPin) warnings.push(t.factoryOther);
  const pinLocked = device !== undefined && device.pinAttemptsLeft === 0;
  if (device && device.pinAttemptsLeft < 3 && !pinLocked) {
    warnings.push(t.pinAttempts(device.pinAttemptsLeft));
  }
  // What vouches that no copy of the key exists: the proof kept in the
  // workspace, or failing that the connected YubiKey's word for it.
  const madeInside = ca.keyAttested
    ? t.keyMadeInside
    : holdsThisCa && device?.ca?.generatedOnDevice
      ? t.keyMadeInsideSaid
      : null;

  return (
    <div className="relative rounded-lg border bg-background px-3 py-2.5 shadow-xs">
      {(onReplace || onTrust || device) && (
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-1 right-1 size-6 text-muted-foreground"
              aria-label={t.actions}
            >
              <Ellipsis className="size-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            {onTrust && <DropdownMenuItem onSelect={onTrust}>{t.trust.menu}</DropdownMenuItem>}
            {onReplace && (
              <DropdownMenuItem onSelect={onReplace}>{t.replaceIssuing}</DropdownMenuItem>
            )}
            {(onReplace || onTrust) && device && <DropdownMenuSeparator />}
            {device && <KeyItems device={device} onKeyTask={onKeyTask} />}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      <p className="text-xs text-muted-foreground">{t.roleInTree[role]}</p>
      <p className="selectable mt-0.5 truncate text-lg font-medium" title={ca.subject}>
        {commonName(ca.subject)}
      </p>
      <p className="mt-0.5 flex items-center gap-1.5 text-muted-foreground">
        {t.validUntil(formatDate(ca.notAfter))}
        {madeInside && (
          <Tooltip>
            <TooltipTrigger asChild>
              <ShieldCheck
                className="size-3.5 text-emerald-600 dark:text-emerald-400"
                aria-label={madeInside}
              />
            </TooltipTrigger>
            <TooltipContent className="max-w-64">{madeInside}</TooltipContent>
          </Tooltip>
        )}
      </p>

      <div className="mt-2 flex items-center gap-1.5 border-t pt-2">
        <span
          className={cn(
            "size-1.5 shrink-0 rounded-full",
            !known && "bg-muted-foreground/30",
            known && device && "bg-connected",
            known && !device && "bg-muted-foreground/40",
          )}
          aria-hidden
        />
        <span className={cn(device ? "text-sidebar-foreground" : "text-muted-foreground")}>
          {device ? t.keyConnected : t.keyNotPresent}
        </span>
        <KeyTag serial={ca.yubikey} className="ml-auto" />
      </div>

      {device?.factoryPin && (
        <div className="mt-1.5 flex items-center gap-1.5 text-xs text-amber-700 dark:text-amber-400">
          <TriangleAlert className="size-3.5 shrink-0" />
          <span className="flex-1">{t.factoryCredentials}</span>
          <Button
            variant="outline"
            size="sm"
            className="h-6 px-2 text-foreground"
            onClick={() => onKeyTask(device, "protect")}
          >
            {t.setOwnPin}
          </Button>
        </div>
      )}
      {device && pinLocked && (
        <div className="mt-1.5 flex items-center gap-1.5 text-xs text-amber-700 dark:text-amber-400">
          <TriangleAlert className="size-3.5 shrink-0" />
          <span className="flex-1">{t.key.pinLocked}</span>
          <Button
            variant="outline"
            size="sm"
            className="h-6 px-2 text-foreground"
            onClick={() => onKeyTask(device, "unblock")}
          >
            {t.key.unblockShort}
          </Button>
        </div>
      )}
      {warnings.map((warning) => (
        <p
          key={warning}
          className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-400"
        >
          <TriangleAlert className="mt-px size-3.5 shrink-0" />
          {warning}
        </p>
      ))}
      {role === "root" &&
        !everyday &&
        device &&
        holdsThisCa &&
        warnings.length === 0 &&
        !device.factoryPin && (
          <p className="mt-1.5 text-xs text-muted-foreground">{t.rootShouldRest}</p>
        )}
    </div>
  );
}
