import { useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Fingerprint,
  LoaderCircle,
  ShieldCheck,
  ShieldPlus,
  TriangleAlert,
} from "lucide-react";

import { KeyName, KeyTag } from "@/components/KeyTag";
import { Secret } from "@/components/Secret";
import { explain } from "@/components/SigningDialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  type Ca,
  type CaRole,
  type Device,
  type Devices,
  type Failure,
  type Pki,
} from "@/lib/api";
import { commonName, formatDate, t } from "@/lib/text";
import { cn } from "@/lib/utils";

interface Props {
  devices: Devices | null;
  /** The open workspace, when all that is wanted is an issuing CA for it:
   *  its first, where the root CA has signed everything itself so far, or
   *  one to take the place of the issuing CA it has. */
  workspace?: Pki;
  onCancel: () => void;
  /** Called with the workspace of the certificate authority just made, or
   *  with the open one as it is after its issuing CA was added, once the
   *  wizard has said so and the user has read it. */
  onCreated: (pki: Pki) => void;
}

type Step = "count" | "keys" | "root" | "issuing";

/**
 * Creates a certificate authority: a root CA on one YubiKey and an issuing
 * CA, signed by it, on another; or, for someone with a single YubiKey, the
 * root CA alone. Given an open workspace, it adds the issuing CA such a
 * root went without, or replaces the issuing CA whose YubiKey is lost.
 * This is the one place where the app writes to a YubiKey, so every step
 * says what it is about to do to which key.
 */
export function SetupWizard({ devices, workspace, onCancel, onCreated }: Props) {
  const [step, setStep] = useState<Step>(workspace ? "keys" : "count");
  // One YubiKey holds the whole authority: a root CA and nothing else.
  const [alone, setAlone] = useState(false);
  const [rootName, setRootName] = useState(workspace ? commonName(workspace.root.subject) : "");
  // The issuing CA of the open workspace that the new one takes over from.
  // As it was when the wizard came up: once the new one is in place, the
  // workspace has that for its issuing CA.
  const [replaced] = useState(workspace?.issuing ?? null);
  const replacedName = replaced ? commonName(replaced.subject) : "";
  const [issuingName, setIssuingName] = useState(replaced ? nextName(replacedName) : "");
  // Stolen rather than lost: the root CA revokes the replaced one as well.
  const [revokeReplaced, setRevokeReplaced] = useState(false);
  const [rootSerial, setRootSerial] = useState<number | null>(workspace?.root.yubikey ?? null);
  const [issuingSerial, setIssuingSerial] = useState<number | null>(null);
  // Kept until the issuing CA is signed: the root has to sign it, and
  // nobody should have to type the same PIN twice within a minute.
  const [rootPin, setRootPin] = useState("");
  const [rootMade, setRootMade] = useState(false);
  // The workspace as it is once everything is made. The wizard does not
  // just vanish then: it says what now exists, and waits to be dismissed.
  const [made, setMade] = useState<Pki | null>(null);
  const at: Step | "done" = made ? "done" : step;

  const keys = devices?.usable ?? [];
  const rootKey = keys.find((key) => key.serial === rootSerial);
  const issuingKey = keys.find((key) => key.serial === issuingSerial);
  // A YubiKey that is pulled out in the middle of its step stays the key
  // of that step, as it was when last seen: the step says to connect it
  // again and keeps what was typed and what it knows of the key. Without
  // that, the step had nothing to show, and came back knowing nothing.
  const seen = useSeen(keys);
  const rootOfStep = rootKey ?? (rootSerial === null ? undefined : seen.get(rootSerial));
  const issuingOfStep =
    issuingKey ?? (issuingSerial === null ? undefined : seen.get(issuingSerial));
  const keysOk =
    rootName.trim() !== "" &&
    rootKey !== undefined &&
    (alone ||
      (issuingName.trim() !== "" && issuingKey !== undefined && issuingSerial !== rootSerial));

  // Adding to a workspace takes two steps: the key, then the making.
  const stepNumber = workspace
    ? step === "keys"
      ? 1
      : 2
    : { count: 1, keys: 2, root: 3, issuing: 4 }[step];
  const steps = workspace ? 2 : alone ? 3 : 4;
  const askWhere = () => api.pickNewFolder(t.adoptWhere, t.workspaceFolderName(rootName.trim()));

  return (
    // The column is centred by its own margins, so that one taller than
    // the window can still be scrolled to its top.
    <div data-tauri-drag-region className="flex h-screen overflow-y-auto p-8">
      <div className="m-auto flex w-full max-w-2xl flex-col">
        <div className="mb-5 flex items-center gap-3">
          <div
            className={cn(
              "flex size-10 shrink-0 items-center justify-center rounded-xl",
              made
                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                : "bg-primary/10 text-primary",
            )}
          >
            {made ? (
              <ShieldCheck className="size-5" strokeWidth={1.75} />
            ) : (
              <ShieldPlus className="size-5" strokeWidth={1.75} />
            )}
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">
              {replaced ? t.replaceIssuingTitle : workspace ? t.addIssuingTitle : t.createTitle}
            </h1>
            <p className="text-xs text-muted-foreground">
              {made ? t.finishedStep : t.createStep(stepNumber, steps)}
            </p>
          </div>
        </div>

        {made && (
          <Finished
            pki={made}
            kind={replaced ? "replaced" : workspace ? "added" : "created"}
            replacedName={replacedName}
            revokedOld={revokeReplaced}
            onDone={() => onCreated(made)}
          />
        )}

        {at === "count" && (
          <>
            <p className="mb-3 font-medium">{t.createHowMany}</p>
            <div className="flex flex-col gap-2" role="radiogroup" aria-label={t.createHowMany}>
              <CountChoice
                checked={!alone}
                onChoose={() => setAlone(false)}
                title={t.createTwo}
                badge={t.createTwoBadge}
                about={t.createTwoAbout}
              />
              <CountChoice
                checked={alone}
                onChoose={() => setAlone(true)}
                title={t.createOne}
                about={t.createOneAbout}
              />
            </div>
            <p className="mt-3 text-xs text-muted-foreground">{t.createKeysNote}</p>
            <Footer onCancel={onCancel}>
              <Button onClick={() => setStep("keys")}>{t.next}</Button>
            </Footer>
          </>
        )}

        {at === "keys" && workspace && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (keysOk) setStep("issuing");
            }}
          >
            <p className="mb-4 text-muted-foreground">
              {replaced
                ? t.replaceIssuingAbout(rootName, replacedName)
                : t.addIssuingAbout(rootName)}
            </p>
            <CaChoice
              role="issuing"
              name={issuingName}
              onName={setIssuingName}
              placeholder={t.createIssuingName}
              keys={keys}
              chosen={issuingSerial}
              taken={rootSerial}
              takenNote={t.holdsWorkspaceRoot}
              onChoose={setIssuingSerial}
            />
            {replaced && (
              <label className="mt-4 flex items-start gap-2.5">
                <Checkbox
                  className="mt-0.5"
                  checked={revokeReplaced}
                  onCheckedChange={(checked) => setRevokeReplaced(checked === true)}
                />
                <span>
                  <span className="block">{t.revokeReplaced}</span>
                  <span className="block text-xs text-muted-foreground">
                    {t.revokeReplacedHint(replacedName)}
                  </span>
                </span>
              </label>
            )}
            {/* The root has to be there to sign. */}
            {devices !== null && rootKey === undefined && (
              <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">
                {t.connectKey(workspace.root.yubikey)}
              </p>
            )}
            <Footer onCancel={onCancel}>
              <Button type="submit" disabled={!keysOk}>
                {t.next}
              </Button>
            </Footer>
          </form>
        )}

        {at === "keys" && !workspace && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (keysOk) setStep("root");
            }}
          >
            <p className="mb-4 text-muted-foreground">{alone ? t.createAboutOne : t.createAbout}</p>
            <div className={cn("grid items-start gap-4", !alone && "grid-cols-2")}>
              <CaChoice
                role="root"
                name={rootName}
                onName={setRootName}
                placeholder={alone ? t.createAloneName : t.createRootName}
                keys={keys}
                chosen={rootSerial}
                taken={alone ? null : issuingSerial}
                onChoose={(serial) => {
                  setRootSerial(serial);
                  // Chosen while one key was to hold everything.
                  if (serial === issuingSerial) setIssuingSerial(null);
                }}
              />
              {!alone && (
                <CaChoice
                  role="issuing"
                  name={issuingName}
                  onName={setIssuingName}
                  placeholder={t.createIssuingName}
                  keys={keys}
                  chosen={issuingSerial}
                  taken={rootSerial}
                  onChoose={setIssuingSerial}
                />
              )}
            </div>
            {!alone && keys.length < 2 && (
              <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">{t.createNeedTwo}</p>
            )}
            <Footer onCancel={onCancel} onBack={() => setStep("count")}>
              <Button type="submit" disabled={!keysOk}>
                {t.next}
              </Button>
            </Footer>
          </form>
        )}

        {at === "root" && rootOfStep && (
          <KeyStep
            key="root"
            role="root"
            name={rootName.trim()}
            device={rootOfStep}
            connected={rootKey !== undefined}
            touchSerial={rootOfStep.serial}
            onCancel={onCancel}
            onBack={() => setStep("keys")}
            // With one YubiKey the root is the whole authority, and its
            // workspace is started along with it.
            place={alone ? askWhere : undefined}
            run={async (setup, onTouch, where) => {
              if (where !== null) {
                setMade(await api.createRootAlone({ key: setup, workspacePath: where }, onTouch));
                return;
              }
              await api.createRoot(setup, onTouch);
              setRootPin(setup.pin);
              setRootMade(true);
              setStep("issuing");
            }}
          />
        )}

        {at === "issuing" && workspace && issuingOfStep && rootSerial !== null && (
          <KeyStep
            key="added"
            role="issuing"
            name={issuingName.trim()}
            device={issuingOfStep}
            connected={issuingKey !== undefined}
            touchSerial={rootSerial}
            signer={{ serial: rootSerial, name: rootName, connected: rootKey !== undefined }}
            onCancel={onCancel}
            onBack={() => setStep("keys")}
            run={async (setup, onTouch, _where, signerPin) => {
              setMade(
                await api.addIssuing(
                  {
                    workspacePath: workspace.path,
                    rootPin: signerPin,
                    key: setup,
                    replacing: replaced !== null,
                    revokeReplaced,
                  },
                  onTouch,
                ),
              );
            }}
          />
        )}

        {at === "issuing" && !workspace && issuingOfStep && rootSerial !== null && (
          <KeyStep
            key="issuing"
            role="issuing"
            name={issuingName.trim()}
            device={issuingOfStep}
            connected={issuingKey !== undefined}
            touchSerial={rootSerial}
            // The root CA was made in the step before, with a touch of
            // its YubiKey, and its PIN is still known from there.
            touchedBefore={rootMade}
            alsoNeeded={rootKey === undefined ? rootSerial : undefined}
            before={rootMade ? t.rootDone(rootName.trim()) : undefined}
            next={rootMade ? t.keepRootConnected : undefined}
            onCancel={onCancel}
            place={askWhere}
            run={async (setup, onTouch, where) => {
              if (where === null) return;
              setMade(
                await api.createIssuing(
                  { rootSerial, rootPin, key: setup, workspacePath: where },
                  onTouch,
                ),
              );
            }}
          />
        )}
      </div>
    </div>
  );
}

/** Every YubiKey that was connected since the wizard came up, as it was
 *  when it was last seen. */
function useSeen(keys: Device[]): Map<number, Device> {
  const [seen, setSeen] = useState(() => new Map<number, Device>());
  // Kept up while rendering, so that a key is known from the moment it
  // shows up; with nothing new to note, nothing is set.
  if (keys.some((key) => seen.get(key.serial) !== key)) {
    const next = new Map(seen);
    for (const key of keys) next.set(key.serial, key);
    setSeen(next);
    return next;
  }
  return seen;
}

/**
 * The last thing the wizard shows: what now exists on which YubiKey, and
 * what is worth doing next. Without it the wizard would close on the touch
 * and leave its user to work out from the sidebar that it had worked.
 */
function Finished({
  pki,
  kind,
  replacedName,
  revokedOld,
  onDone,
}: {
  pki: Pki;
  /** A new authority, an issuing CA for one that had none, or one in
   *  place of the issuing CA it had. */
  kind: "created" | "added" | "replaced";
  replacedName: string;
  /** The replaced issuing CA was revoked along the way. */
  revokedOld: boolean;
  onDone: () => void;
}) {
  const next = [
    kind === "replaced" &&
      (revokedOld ? t.finishedRevoked(replacedName) : t.finishedOldStays(replacedName)),
    !pki.issuing
      ? t.finishedAlone
      : kind === "replaced" && revokedOld
        ? t.finishedRootRestAfter(pki.root.yubikey)
        : t.finishedRootRest(pki.root.yubikey),
    kind === "created" && t.finishedWorkspace(pki.path),
    kind === "created" && t.finishedTrust,
  ].filter((note): note is string => Boolean(note));

  return (
    <div className="flex flex-col gap-4">
      <p className="flex items-start gap-2.5 rounded-lg bg-emerald-500/10 px-3 py-2.5 font-medium text-emerald-700 dark:text-emerald-400">
        <Check className="mt-0.5 size-4 shrink-0" />
        {t.finished[kind]}
      </p>
      <ul className="divide-y rounded-xl border">
        <MadeCa role="root" ca={pki.root} />
        {pki.issuing && <MadeCa role="issuing" ca={pki.issuing} />}
      </ul>
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">{t.finishedNext}</p>
        <ul className="flex flex-col gap-1.5">
          {next.map((note) => (
            <li key={note} className="selectable flex items-start gap-2.5">
              <span
                aria-hidden
                className="mt-2 size-1 shrink-0 rounded-full bg-muted-foreground/70"
              />
              {note}
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-1 flex justify-end">
        <Button autoFocus onClick={onDone}>
          {t.done}
        </Button>
      </div>
    </div>
  );
}

/** One CA of the finished authority, and the YubiKey it lives on. */
function MadeCa({ role, ca }: { role: CaRole; ca: Ca }) {
  return (
    <li className="flex items-baseline justify-between gap-3 px-4 py-2.5">
      <span className="selectable min-w-0 font-medium">
        {t.createOn(t.role[role], commonName(ca.subject))} <KeyTag serial={ca.yubikey} />
      </span>
      <span className="shrink-0 text-xs text-muted-foreground">
        {t.validUntil(formatDate(ca.notAfter))}
      </span>
    </li>
  );
}

/** A name for the CA that takes over from one called `name`. */
function nextName(name: string): string {
  const numbered = name.match(/^(.*?)(\d+)$/);
  return numbered ? `${numbered[1]}${Number(numbered[2]) + 1}` : `${name} 2`;
}

/** One of the two ways to keep a certificate authority. */
function CountChoice({
  checked,
  onChoose,
  title,
  badge,
  about,
}: {
  checked: boolean;
  onChoose: () => void;
  title: string;
  badge?: string;
  about: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      onClick={onChoose}
      className={cn(
        "flex items-start gap-3 rounded-xl border px-4 py-3 text-left transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
        checked ? "border-primary bg-primary/5" : "hover:bg-muted/60",
      )}
    >
      <span
        className={cn(
          "mt-[3px] flex size-3.5 shrink-0 items-center justify-center rounded-full border",
          checked ? "border-primary" : "border-muted-foreground/50",
        )}
      >
        {checked && <span className="size-1.5 rounded-full bg-primary" />}
      </span>
      <span>
        <span className="flex items-center gap-2 font-medium">
          {title}
          {badge && (
            <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              {badge}
            </span>
          )}
        </span>
        <span className="mt-1 block text-muted-foreground">{about}</span>
      </span>
    </button>
  );
}

/** The buttons under a step: leaving on the left, moving on the right. */
function Footer({
  onCancel,
  onBack,
  className,
  children,
}: {
  onCancel: () => void;
  onBack?: () => void;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("mt-5 flex items-center gap-2", className)}>
      <Button type="button" variant="ghost" className="mr-auto" onClick={onCancel}>
        {t.cancel}
      </Button>
      {onBack && (
        <Button type="button" variant="outline" onClick={onBack}>
          <ArrowLeft />
          {t.back}
        </Button>
      )}
      {children}
    </div>
  );
}

/** Name and YubiKey of one CA. */
function CaChoice({
  role,
  name,
  onName,
  placeholder,
  keys,
  chosen,
  taken,
  takenNote,
  onChoose,
}: {
  role: CaRole;
  name: string;
  onName: (name: string) => void;
  placeholder: string;
  keys: Device[];
  chosen: number | null;
  /** The key the other CA is going on, or is on already. */
  taken: number | null;
  /** Said of that key, if not that it was chosen for the other CA. */
  takenNote?: string;
  /** Told the key that was chosen, or nothing when the choice is taken
   *  back. */
  onChoose: (serial: number | null) => void;
}) {
  return (
    <section className="rounded-xl border">
      <p className="border-b px-4 py-2 text-xs font-medium text-muted-foreground">{t.role[role]}</p>
      <div className="flex flex-col gap-3 px-4 py-3">
        <div className="flex flex-col gap-1.5">
          <Label>{t.createName}</Label>
          <Input
            value={name}
            onChange={(event) => onName(event.target.value)}
            placeholder={placeholder}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label>{t.createKey}</Label>
          {keys.length === 0 ? (
            <p className="text-muted-foreground">{t.noKeysConnected}</p>
          ) : (
            <div className="flex flex-col gap-1.5" role="radiogroup">
              {keys.map((key) => {
                const elsewhere = key.serial === taken;
                const checked = key.serial === chosen;
                return (
                  <button
                    key={key.serial}
                    type="button"
                    role="radio"
                    aria-checked={checked}
                    disabled={elsewhere}
                    // A second click takes the choice back. With two keys,
                    // each chosen for one CA, neither could otherwise be
                    // given to the other any more.
                    onClick={() => onChoose(checked ? null : key.serial)}
                    className={cn(
                      "flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-left transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50",
                      checked ? "border-primary bg-primary/5" : "enabled:hover:bg-muted/60",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-[3px] flex size-3.5 shrink-0 items-center justify-center rounded-full border",
                        checked ? "border-primary" : "border-muted-foreground/50",
                      )}
                    >
                      {checked && <span className="size-1.5 rounded-full bg-primary" />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline justify-between gap-2">
                        <KeyName serial={key.serial} />
                        <span
                          title={t.firmwareAbout(key.firmware)}
                          className="shrink-0 text-xs whitespace-nowrap text-muted-foreground"
                        >
                          {t.firmware(key.firmware)}
                        </span>
                      </span>
                      <KeyState
                        device={key}
                        elsewhere={elsewhere ? (takenNote ?? t.createTaken) : null}
                      />
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

/** What a YubiKey holds now, and so what putting a CA on it will cost. */
function KeyState({
  device,
  elsewhere,
}: {
  device: Device;
  /** Why the key is not to be had, if it is not. */
  elsewhere: string | null;
}) {
  if (elsewhere !== null) {
    return <span className="mt-0.5 block text-xs text-muted-foreground">{elsewhere}</span>;
  }
  if (device.slotInUse) {
    return (
      <span className="mt-0.5 block text-xs text-amber-700 dark:text-amber-400">
        {holds(device)} {t.destroyedForNew}
      </span>
    );
  }
  return (
    <span className="mt-0.5 block text-xs text-muted-foreground">
      {device.factoryPin ? t.keyFresh : t.keyEmpty}
    </span>
  );
}

/** What the CA slot of a YubiKey holds that a new CA would destroy. */
function holds(device: Device): string {
  if (device.ca) return t.keyHolds(t.roleInText[device.ca.role], commonName(device.ca.subject));
  return device.keyWithoutCertificate ? t.keyHoldsLoneKey : t.keyHoldsSomething;
}

/** Failures that are about a YubiKey, and so say nothing against the
 *  folder that was chosen for the workspace. */
const aboutKey: Failure["kind"][] = [
  "wrong-pin",
  "pin-locked",
  "last-attempt",
  "not-touched",
  "key-missing",
  "interrupted",
];

/**
 * One YubiKey getting its CA: the PIN (a new one, with a PUK, for a key
 * fresh from the box), the confirmation if something is destroyed, and
 * then the key itself at work.
 */
function KeyStep({
  role,
  name,
  device,
  connected,
  touchSerial,
  touchedBefore,
  alsoNeeded,
  before,
  next,
  signer,
  onCancel,
  onBack,
  place,
  run,
}: {
  role: CaRole;
  name: string;
  /** The YubiKey that gets the CA, as it was when last seen. */
  device: Device;
  /** Whether it is plugged in right now. Pulled out, the step waits for
   *  it and keeps what was typed. */
  connected: boolean;
  /** The YubiKey that signs and so waits for the touch. */
  touchSerial: number;
  /** That YubiKey was touched a moment ago, for the CA made before this
   *  one: a way to tell it from the other without reading a number. */
  touchedBefore?: boolean;
  /** Another YubiKey this step needs and does not find: the root CA that
   *  signs, where its PIN is known already. */
  alsoNeeded?: number;
  /** Said above the form, about what happened so far. */
  before?: string;
  /** Said under that, about what to do now; told whether this YubiKey is
   *  fresh from the box and so gets a PIN of its own. */
  next?: (fresh: boolean) => string;
  /** The root CA that signs, where its PIN has to be asked for here
   *  because it was not given a moment ago. */
  signer?: { serial: number; name: string; connected: boolean };
  onCancel: () => void;
  onBack?: () => void;
  /** Asks where the workspace folder goes, before anything is written to
   *  the YubiKey; `null` calls the step off. */
  place?: () => Promise<string | null>;
  run: (
    setup: { serial: number; name: string; pin: string; newPuk: string | null; replace: boolean },
    onTouch: () => void,
    /** What `place` answered, or `null` without one. */
    where: string | null,
    /** The PIN of `signer`; empty without one. */
    signerPin: string,
  ) => Promise<void>;
}) {
  // Decided once: after a new PIN is set the key no longer looks fresh,
  // but the form must not change under the person filling it in.
  const [fresh] = useState(device.factoryPin);
  const [pin, setPin] = useState("");
  const [pinRepeat, setPinRepeat] = useState("");
  const [puk, setPuk] = useState("");
  const [pukRepeat, setPukRepeat] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [signerPin, setSignerPin] = useState("");
  // A failed attempt may have left an unfinished key in the slot. It is
  // this step's own, so the next attempt replaces it without asking: what
  // the slot held before is gone by then, and that was asked about.
  const [interrupted, setInterrupted] = useState(false);
  // Where the workspace goes is asked once; trying again does not ask anew.
  const [chosenPlace, setChosenPlace] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [touching, setTouching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const destroys = device.slotInUse && !interrupted;
  // By the time a key was made, a YubiKey fresh from the box has the PIN
  // and PUK chosen here. They cannot be chosen again.
  const credentialsSet = fresh && interrupted;
  const lengthOk = (value: string) => value.length >= 6 && value.length <= 8;
  const credentialsOk =
    (fresh
      ? lengthOk(pin) && pin === pinRepeat && lengthOk(puk) && puk === pukRepeat
      : pin.length >= 6) &&
    (!signer || (signer.connected && signerPin.length >= 6));
  const confirmed = !destroys || confirmation.trim() === String(device.serial);
  // What is wrong with a new PIN and PUK as they stand, while they are
  // being typed.
  const amiss =
    (pinRepeat !== "" && pin !== pinRepeat) || (pukRepeat !== "" && puk !== pukRepeat)
      ? t.credentialsDiffer
      : (pin !== "" && !lengthOk(pin)) || (puk !== "" && !lengthOk(puk))
        ? t.credentialLength
        : null;
  // Both YubiKeys have to be there before anything is started.
  const ready = connected && alsoNeeded === undefined && credentialsOk && confirmed;

  async function start() {
    setError(null);
    const where = chosenPlace ?? (place ? await place() : null);
    // Nothing has been written yet; the step simply waits.
    if (place && where === null) return;
    setChosenPlace(where);
    setBusy(true);
    setTouching(false);
    try {
      await run(
        {
          serial: device.serial,
          name,
          pin,
          newPuk: fresh ? puk : null,
          replace: device.slotInUse || interrupted,
        },
        () => setTouching(true),
        where,
        signerPin,
      );
    } catch (reason) {
      const failure = reason as Failure;
      setError(
        failure.kind === "interrupted" && failure.notTouched
          ? // Which of two YubiKeys was not touched is what went wrong.
            touchSerial === device.serial
            ? t.failure.untouched
            : t.failure.untouchedRoot(touchSerial)
          : explain(failure),
      );
      if (failure.kind === "interrupted") setInterrupted(true);
      // Anything else may be about the folder, which is then asked for
      // again.
      if (!aboutKey.includes(failure.kind)) setChosenPlace(null);
      // A PIN that was just chosen stays; one that was wrong is typed
      // again, on the key that refused it.
      if (failure.kind === "wrong-pin") {
        if (signer && failure.serial === signer.serial) setSignerPin("");
        else if (!fresh) setPin("");
      }
    } finally {
      setBusy(false);
    }
  }

  if (busy) {
    // Two YubiKeys may be at work here, one after the other: the one that
    // gets the key, and for an issuing CA the root's, which signs it.
    // Only the one that signs wants a touch. So one thing is said at a
    // time, the touch is asked for when that key starts to blink, and its
    // serial number is the only one shown.
    const itself = touchSerial === device.serial;
    return (
      <div className="flex flex-col items-center gap-3 rounded-xl border px-6 py-10 text-center">
        {touching ? (
          <>
            <span className="relative flex size-14 items-center justify-center">
              <span className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
              <span className="relative flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Fingerprint className="size-7" strokeWidth={1.5} />
              </span>
            </span>
            <p className="text-xl font-medium">{itself ? t.touchTitle : t.touchRootTitle}</p>
            <KeyTag serial={touchSerial} className="px-2 py-0.5 text-sm leading-[18px]" />
            <p className="max-w-sm text-sm text-muted-foreground">
              {itself ? t.touchHint : touchedBefore ? t.touchRootAgainHint : t.touchRootHint}
            </p>
          </>
        ) : (
          <>
            <LoaderCircle className="size-7 animate-spin text-muted-foreground" />
            <p className="text-sm text-muted-foreground">{t.makingKey(t.roleInText[role])}</p>
          </>
        )}
      </div>
    );
  }

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (ready) void start();
      }}
    >
      {(before || next) && (
        // Two things, said apart: what went well, and what to do now. Read
        // as one, the second is easily missed, and with it the reason a
        // PIN is asked for again.
        <div className="flex flex-col gap-1.5">
          {before && (
            <p className="flex items-start gap-2.5 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-emerald-700 dark:text-emerald-400">
              <Check className="mt-0.5 size-4 shrink-0" />
              {before}
            </p>
          )}
          {next && (
            <p className="flex items-start gap-2.5 rounded-lg bg-muted/60 px-3 py-2.5">
              <ArrowRight className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              {next(fresh)}
            </p>
          )}
        </div>
      )}
      <section className="rounded-xl border">
        <p className="border-b px-4 py-2 font-medium">
          {t.createOn(t.role[role], name)} <KeyTag serial={device.serial} />
        </p>
        <div className="flex flex-col gap-4 px-4 py-3">
          {!connected ? (
            // Pulled out: what was typed is kept, and comes back with it.
            <p className="text-amber-700 dark:text-amber-400">{t.connectKey(device.serial)}</p>
          ) : credentialsSet ? (
            <p className="text-muted-foreground">{t.credentialsSet}</p>
          ) : fresh ? (
            <>
              <div className="grid max-w-md grid-cols-2 gap-3">
                <Secret label={t.newPin} value={pin} onChange={setPin} autoFocus />
                <Secret
                  label={t.newPinRepeat}
                  value={pinRepeat}
                  onChange={setPinRepeat}
                  invalid={pinRepeat !== "" && pin !== pinRepeat}
                />
                <Secret label={t.newPuk} value={puk} onChange={setPuk} />
                <Secret
                  label={t.newPukRepeat}
                  value={pukRepeat}
                  onChange={setPukRepeat}
                  invalid={pukRepeat !== "" && puk !== pukRepeat}
                />
              </div>
              {/* What is wrong with what was typed is said in the place of
                  the hint, and the hint keeps its room meanwhile: this
                  changes with every key that is pressed, and nothing
                  below it may move for that. */}
              <p className="-mt-1 grid text-xs text-muted-foreground">
                <span className={cn("col-start-1 row-start-1", amiss && "invisible")}>
                  {t.newCredentialsHint}
                </span>
                {amiss && (
                  <span className="col-start-1 row-start-1 text-destructive">{amiss}</span>
                )}
              </p>
            </>
          ) : (
            <Secret
              label={t.pinOf}
              serial={device.serial}
              // Worth saying only where another key's PIN is asked for too.
              hint={signer ? t.pinOfNewKey(t.roleInText[role]) : undefined}
              fieldClassName="w-60"
              value={pin}
              onChange={setPin}
              autoFocus
            />
          )}

          {connected && destroys && (
            <div className="flex flex-col gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2.5">
              <p className="flex items-start gap-2 text-destructive">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                {holds(device)} {t.destroyedForNew} {t.cannotBeUndone}
              </p>
              {/* A whole sentence stands over this field, not a word or
                  two, and wants more room above it than a label does. */}
              <div className="flex flex-col gap-2.5">
                <Label className="font-normal">{t.destroyConfirm(device.serial)}</Label>
                <Input
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  inputMode="numeric"
                  autoComplete="off"
                  className="w-44 tabular-nums"
                />
              </div>
            </div>
          )}
        </div>
      </section>

      {signer && (
        <section className="rounded-xl border">
          <p className="border-b px-4 py-2 font-medium">
            {t.signedByRootOn(signer.name)} <KeyTag serial={signer.serial} />
          </p>
          <div className="px-4 py-3">
            {signer.connected ? (
              <Secret
                label={t.pinOf}
                serial={signer.serial}
                hint={t.pinOfSigner}
                fieldClassName="w-60"
                value={signerPin}
                onChange={setSignerPin}
              />
            ) : (
              <p className="text-amber-700 dark:text-amber-400">{t.connectKey(signer.serial)}</p>
            )}
          </div>
        </section>
      )}

      {alsoNeeded !== undefined && (
        <p className="text-amber-700 dark:text-amber-400">{t.connectKey(alsoNeeded)}</p>
      )}

      {error && (
        <p className="selectable flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-destructive">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          {error}
        </p>
      )}

      <Footer onCancel={onCancel} onBack={onBack} className="mt-1">
        <Button type="submit" variant={destroys ? "destructive" : "default"} disabled={!ready}>
          {role === "root" ? t.createRoot : t.createIssuing}
        </Button>
      </Footer>
    </form>
  );
}
