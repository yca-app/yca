import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Bot,
  Check,
  ChevronRight,
  FileKey2,
  FileText,
  Fingerprint,
  LoaderCircle,
  TriangleAlert,
} from "lucide-react";

import { FilesChoice } from "@/components/FilesChoice";
import { KeyName, KeyTag } from "@/components/KeyTag";
import { useShortPath } from "@/components/PathTail";
import { GroupPicker } from "@/components/GroupPicker";
import { SecretInput } from "@/components/Secret";
import { Segmented } from "@/components/Segmented";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  holdsCa,
  type AgentReply,
  type CaRole,
  type Certificate,
  type Devices,
  type Failure,
  type Files,
  type Issued,
  type KeyKind,
  type Pki,
  type Profile,
} from "@/lib/api";
import { profileIcon, profiles } from "@/lib/profiles";
import { commonName, formatDate, t } from "@/lib/text";
import { cn } from "@/lib/utils";

/** What the upload form mostly asks for, by what the certificate is for.
 *  Only where the dialog starts: the person says what theirs asks for. */
const usualFiles: Record<Profile, Files> = {
  "tls-server": "fullchain",
  "ipsec-gateway": "separate",
  "ipsec-client": "p12",
  "tls-client": "p12",
};

const isServer = (profile: Profile) => profile === "tls-server" || profile === "ipsec-gateway";

/**
 * How long a certificate can be asked to last, in days; `null` is as long
 * as possible. A TLS server certificate is cut off at 825 days whatever is
 * asked, so nothing longer is offered for one.
 */
const validityChoices = (profile: Profile, asked: number | null = null): (number | null)[] => {
  const usual = profile === "tls-server" ? [null, 365, 90] : [null, 1825, 730, 365];
  // A length a program asked for that is none of the usual ones is shown
  // as one more choice, so that what will be signed is in plain sight.
  return asked === null || usual.includes(asked) ? usual : [...usual, asked];
};
const keyKinds: KeyKind[] = ["rsa", "ecdsa"];

type Step = "kind" | "details" | "pin" | "signing" | "done";

/**
 * Where the dialog stands, as far as the rest of the window needs to know:
 * being filled in, waiting for the YubiKey, or showing a result that is
 * only there to be read.
 */
export type Progress = "filling" | "signing" | "done";

/**
 * What a program asked for on the person's behalf. The dialog opens
 * filled in with it and says who asks; the person can change anything,
 * and nothing is signed until they have typed the PIN and touched the key.
 */
export interface Asked {
  /** The id of the program's request. */
  id: string;
  /** Who asks, as the program called itself. */
  from: string;
  /** What was asked for; whatever is left out is as usual. */
  profile?: Profile;
  names?: string[];
  files?: Files;
  days?: number | null;
  key?: KeyKind;
  p12Compatible?: boolean;
  signWithRoot?: boolean;
  /** The request file of a device that keeps its own key. */
  csrPath?: string;
  revokeOld?: boolean;
  /** Tells the program how it ended. */
  answer: (reply: AgentReply) => void;
}

/** What a YubiKey is asked to sign. */
export type Task =
  /** A new certificate with a new key, and the group it goes into unless
   *  its owner says otherwise. */
  | { kind: "new"; group?: string | null; asked?: Asked }
  /** A certificate for the key of an existing one: new names or more time. */
  | { kind: "renew"; certificate: Certificate; asked?: Asked }
  /** The same, but for other host names, addresses or another name. */
  | { kind: "change"; certificate: Certificate; asked?: Asked }
  /** The revocation list of one CA. */
  | { kind: "list"; role: CaRole; asked?: Asked };

/** Where each task begins: only a new certificate asks what it is for,
 *  unless a program said so already, and a revocation list has nothing to
 *  fill in. */
const firstStep = (task: Task): Step =>
  task.kind === "new"
    ? task.asked?.profile
      ? "details"
      : "kind"
    : task.kind === "list"
      ? "pin"
      : "details";

/** The certificate a task issues again for the same key, if it does that. */
const earlier = (task: Task): Certificate | null =>
  task.kind === "renew" || task.kind === "change" ? task.certificate : null;

/** What the last step shows once the YubiKey has signed. */
interface Outcome {
  title: string;
  summary: string;
  headline: string;
  note?: string;
  /** The root CA signed it itself, so no issuing CA comes with it. */
  fromRoot?: boolean;
  /** Say that the root CA has to be trusted where the certificate is
   *  used, and offer the way to it. Not after a revocation list. */
  trust?: boolean;
  folder: string;
  files: Issued["files"];
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  task: Task;
  pki: Pki;
  devices: Devices | null;
  /** Called after something was signed, so the list can reload. */
  onSigned: () => void;
  /** Called as the dialog goes from one stage to the next. */
  onProgress?: (progress: Progress) => void;
  /** Called to show how devices are made to trust the root CA. */
  onTrust?: () => void;
}

/**
 * Everything that ends with a signature from a YubiKey goes through this
 * dialog, so the PIN and the touch look and behave the same each time:
 * a new certificate, one issued again for the same key, a revocation list.
 */
export function SigningDialog({
  open,
  onOpenChange,
  task,
  pki,
  devices,
  onSigned,
  onProgress,
  onTrust,
}: Props) {
  const [step, setStep] = useState<Step>("kind");
  const [chosenProfile, setProfile] = useState<Profile>("tls-server");
  const [names, setNames] = useState("");
  const [files, setFiles] = useState<Files>("fullchain");
  const [password, setPassword] = useState("");
  const [passwordRepeat, setPasswordRepeat] = useState("");
  // The password of the .p12 file a renewed certificate's key is in.
  const [opens, setOpens] = useState("");
  const [signWithRoot, setSignWithRoot] = useState(false);
  const [revokeOld, setRevokeOld] = useState(true);
  // The choices most people leave as they are, and whether they show.
  const [showOptions, setShowOptions] = useState(false);
  const [days, setDays] = useState<number | null>(null);
  const [keyKind, setKeyKind] = useState<KeyKind>("rsa");
  const [p12Compatible, setP12Compatible] = useState(false);
  // The group a new certificate is sorted into; none unless one is named.
  const [group, setGroup] = useState<string | null>(null);
  // The request file of a device that made its own key, once chosen.
  const [requestPath, setRequestPath] = useState<string | null>(null);
  const [pin, setPin] = useState("");
  const [touching, setTouching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  // Every time the dialog opens it starts from scratch.
  useEffect(() => {
    if (!open) return;
    setStep(firstStep(task));
    setNames(earlier(task)?.names.join(", ") ?? "");
    setPassword("");
    setPasswordRepeat("");
    setOpens("");
    setSignWithRoot(false);
    setRevokeOld(true);
    setShowOptions(false);
    setDays(null);
    setKeyKind("rsa");
    setP12Compatible(false);
    setGroup(task.kind === "new" ? (task.group ?? null) : null);
    setRequestPath(null);
    setPin("");
    setTouching(false);
    setError(null);
    setOutcome(null);
    answered.current = false;
    // What a program asked for is filled in, for the person to check.
    const asked = task.asked;
    if (!asked) return;
    if (task.kind === "new" && asked.profile) {
      setProfile(asked.profile);
      setFiles(asked.files ?? usualFiles[asked.profile]);
    }
    if (asked.names && asked.names.length > 0) setNames(asked.names.join(", "));
    if (asked.days !== undefined) setDays(asked.days);
    if (asked.key) setKeyKind(asked.key);
    setP12Compatible(asked.p12Compatible ?? false);
    setSignWithRoot(asked.signWithRoot ?? false);
    setRequestPath(asked.csrPath ?? null);
    if (asked.revokeOld !== undefined) setRevokeOld(asked.revokeOld);
    // Whatever is not as usual is in plain sight, not folded away.
    setShowOptions(
      (asked.days ?? null) !== null || asked.key === "ecdsa" || asked.p12Compatible === true,
    );
  }, [open, task]);

  // The program that asked is told how it ended, once: done, or put away.
  const answered = useRef(false);
  const tell = (reply: AgentReply) => {
    if (!task.asked || answered.current) return;
    answered.current = true;
    task.asked.answer(reply);
  };
  const close = () => {
    tell({ state: "declined" });
    onOpenChange(false);
  };

  // Each step starts with the cursor in its first field, so the whole
  // dialog can be driven from the keyboard.
  const firstField = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!open || (step !== "details" && step !== "pin")) return;
    const frame = requestAnimationFrame(() => firstField.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open, step]);

  const old = earlier(task);
  const profile = old?.profile ?? chosenProfile;
  // The groups this workspace has, by name.
  const groups = useMemo(
    () =>
      [...new Set(pki.certificates.flatMap((c) => (c.group === null ? [] : [c.group])))].sort(
        (a, b) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true }),
      ),
    [pki],
  );
  // A new certificate comes from the issuing CA unless the device cannot
  // handle a chain, or the whole authority is a root CA on one YubiKey;
  // one issued again comes from the CA that signed the old one; a
  // revocation list is signed by the CA whose list it is.
  const role: CaRole =
    task.kind === "new"
      ? signWithRoot || pki.issuing === null
        ? "root"
        : "issuing"
      : task.kind === "list"
        ? task.role
        : task.certificate.issuedBy;
  const signer = role === "root" ? pki.root : pki.issuing;
  const signerConnected =
    signer !== null &&
    (devices?.usable ?? []).some(
      (device) => device.serial === signer.yubikey && holdsCa(device, role, signer),
    );
  const attemptsLeft = (devices?.usable ?? []).find(
    (device) => device.serial === signer?.yubikey,
  )?.pinAttemptsLeft;

  const nameList = names
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  // A password is only for the one file that carries a private key.
  const needsPassword = task.kind === "new" && files === "p12" && requestPath === null;
  // A key is made here unless the device made its own or keeps the old one.
  const makesKey = task.kind === "new" && requestPath === null;
  const passwordsOk = !needsPassword || (password !== "" && password === passwordRepeat);
  // A renewal writes the key again, so out of a .p12 file it takes the
  // file's password; the new file gets the same one.
  const needsOpens = old !== null && old.form === "p12" && old.hasKey;
  const namesOk = nameList.length > 0 && (isServer(profile) || nameList.length === 1);
  // Asking for other names and then leaving them alone would be a renewal.
  const namesChanged = old !== null && nameList.join("\n") !== old.names.join("\n");
  const detailsOk =
    (!needsOpens || opens !== "") &&
    (task.kind === "renew"
      ? true
      : task.kind === "change"
        ? namesOk && namesChanged
        : namesOk && passwordsOk);
  // What ends up in the certificate.
  const finalNames = task.kind === "renew" && old ? old.names : nameList;
  // Only a certificate that is still valid can be revoked, and only while
  // the CA that signed it is there to list it.
  const canRevokeOld =
    old !== null &&
    old.issuer === "current" &&
    (old.status === "valid" || old.status === "expires-soon");

  /** Takes a device's request file: the names it asks for are offered,
   *  and what is certified is whatever stands in the field afterwards. */
  async function chooseRequest() {
    const path = await api.pickRequestFile(t.requestPick);
    if (!path) return;
    try {
      const asked = await api.readRequest(path);
      setRequestPath(path);
      if (asked.names.length > 0) setNames(asked.names.join(", "));
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }

  function chooseKind(chosen: Profile) {
    setProfile(chosen);
    setFiles(usualFiles[chosen]);
    setSignWithRoot(false);
    // What can be asked for depends on what the certificate is for.
    setDays(null);
    setStep("details");
  }

  async function sign() {
    setStep("signing");
    onProgress?.("signing");
    setTouching(false);
    setError(null);
    const touched = () => setTouching(true);
    try {
      if (task.kind === "list") {
        const signed = await api.signRevocationList(
          { pkiPath: pki.path, role: task.role, pin },
          touched,
        );
        setOutcome({
          title: t.listDoneTitle,
          summary: t.listDone(signed.number, formatDate(signed.nextUpdate)),
          headline: t.listCount(signed.count),
          folder: signed.folder,
          files: signed.files,
        });
        tell({
          state: "done",
          result: {
            number: signed.number,
            nextUpdate: signed.nextUpdate,
            revokedCertificates: signed.count,
            folder: signed.folder,
            files: signed.files.map((file) => file.name),
          },
        });
      } else {
        const issued =
          old !== null
            ? await api.reissue(
                {
                  pkiPath: pki.path,
                  serial: old.serial,
                  // No names means: keep the ones it has.
                  names: task.kind === "change" ? nameList : [],
                  revokeOld: revokeOld && canRevokeOld,
                  days,
                  opens: needsOpens ? opens : null,
                  pin,
                },
                touched,
              )
            : requestPath !== null
              ? await api.signRequest(
                  {
                    pkiPath: pki.path,
                    csrPath: requestPath,
                    profile,
                    names: nameList,
                    // Nothing goes into one file where there is no key.
                    files: files === "p12" ? "fullchain" : files,
                    signWithRoot: role === "root",
                    days,
                    group,
                    pin,
                  },
                  touched,
                )
              : await api.issue(
                  {
                    pkiPath: pki.path,
                    profile,
                    names: nameList,
                    files,
                    p12Password: files === "p12" ? password : null,
                    signWithRoot: role === "root",
                    days,
                    key: keyKind,
                    p12Compatible: files === "p12" && p12Compatible,
                    group,
                    pin,
                  },
                  touched,
                );
        setOutcome({
          title: t.doneTitle,
          summary: t.doneValid(formatDate(issued.notAfter)),
          headline: finalNames.join(", "),
          note: old !== null ? t.renewDoneNote : requestPath !== null ? t.requestNote : undefined,
          fromRoot: role === "root",
          trust: true,
          folder: issued.folder,
          files: issued.files,
        });
        tell({
          state: "done",
          result: {
            serial: issued.serial,
            names: finalNames,
            notAfter: issued.notAfter,
            signedBy: role,
            folder: issued.folder,
            files: issued.files.map((file) => file.name),
          },
        });
      }
      setPin("");
      setStep("done");
      onProgress?.("done");
      onSigned();
    } catch (reason) {
      onProgress?.("filling");
      const failure = reason as Failure;
      setError(explain(failure));
      // A wrong PIN has to be typed again; a missed touch does not.
      if (failure.kind !== "not-touched") setPin("");
      // A revocation list has no step before the PIN to go back to. A
      // wrong password for the file is told where it is typed; the
      // YubiKey was not asked for anything.
      setStep(
        (failure.kind === "key-missing" && task.kind !== "list") ||
          failure.kind === "wrong-password"
          ? "details"
          : "pin",
      );
    }
  }

  const title =
    step === "done" && outcome
      ? outcome.title
      : task.kind === "new"
        ? t.newTitle
        : task.kind === "renew"
          ? t.renewTitle
          : task.kind === "change"
            ? t.changeNamesTitle[isServer(profile) ? "server" : "client"]
            : t.listTitle;
  const subject =
    task.kind === "list"
      ? signer
        ? `${t.role[role]} “${commonName(signer.subject)}”`
        : t.role[role]
      : old !== null
        ? `${t.profile[profile]} · ${old.names.join(", ")}`
        : `${t.profile[profile]} · ${nameList.join(", ")}`;

  // While the YubiKey is signing the dialog cannot be dismissed.
  const busy = step === "signing";
  const folderShown = useShortPath(outcome?.folder ?? "");

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (busy) return;
        if (next) onOpenChange(true);
        else close();
      }}
    >
      <DialogContent
        // Taller than a small window once the options are unfolded.
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-[calc(34rem+6px)]"
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <div className="flex items-center justify-between gap-3">
            <DialogDescription>
              {step === "kind" && t.stepKind}
              {step === "details" && (old !== null ? subject : t.profileTitle[profile])}
              {(step === "pin" || step === "signing") && subject}
              {step === "done" && outcome?.summary}
            </DialogDescription>
            {/* Which group a new certificate goes into. Beside the line that
                says what it is for, where it costs the dialog no room; one
                issued again stays in the group of the one it replaces. */}
            {step === "details" && task.kind === "new" && (
              <GroupPicker
                group={group}
                groups={groups}
                onChange={setGroup}
                className="-my-1 shrink-0"
              />
            )}
          </div>
        </DialogHeader>

        {/* Who asks, when it is not the person at the window. */}
        {task.asked && (step === "details" || step === "pin" || step === "signing") && (
          <p className="flex items-start gap-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
            <Bot className="mt-0.5 size-4 shrink-0 text-primary" />
            <span>
              <span className="font-medium">{t.agent.asks(task.asked.from)}</span>{" "}
              {t.agent.checkSign}
            </span>
          </p>
        )}

        {step === "kind" && (
          <div className="grid grid-cols-2 gap-2">
            {profiles.map((kind) => {
              const Icon = profileIcon[kind];
              return (
                <button
                  key={kind}
                  onClick={() => chooseKind(kind)}
                  className="flex flex-col gap-2 rounded-lg border p-3 text-left transition-colors outline-none hover:border-primary/60 hover:bg-primary/5 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                >
                  <Icon className="size-5 text-primary" strokeWidth={1.75} />
                  <span>
                    <span className="block font-medium">{t.profileTitle[kind]}</span>
                    <span className="block text-xs text-muted-foreground">
                      {t.profileHint[kind]}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {step === "details" && (
          <form
            id="details"
            className="flex flex-col gap-5"
            onSubmit={(event) => {
              event.preventDefault();
              if (detailsOk && signerConnected) {
                setError(null);
                setStep("pin");
              }
            }}
          >
            {/* A renewal has nothing to fill in: same key, same names. */}
            {task.kind === "renew" ? (
              <p className="text-sm text-muted-foreground">{t.renewAbout}</p>
            ) : (
              <Field
                label={
                  task.kind === "change"
                    ? isServer(profile)
                      ? t.newNamesServer
                      : t.newNameClient
                    : isServer(profile)
                      ? t.namesServer
                      : t.nameClient
                }
                hint={
                  task.kind === "change"
                    ? isServer(profile)
                      ? t.changeNamesHintServer
                      : t.changeNamesHint
                    : isServer(profile)
                      ? t.namesServerHint
                      : undefined
                }
              >
                <Input
                  ref={firstField}
                  value={names}
                  onChange={(event) => setNames(event.target.value)}
                  placeholder={
                    isServer(profile) ? t.namesServerPlaceholder : t.nameClientPlaceholder
                  }
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  className={fieldHeight}
                />
              </Field>
            )}

            {task.kind === "new" && (
              <>
                {/* Where the key comes from is one question, and how the
                    device takes the files another: a device that made its
                    own key takes its certificate through a form too. */}
                <div>
                  <label className="flex items-start gap-2.5">
                    <Checkbox
                      className="mt-0.5"
                      checked={requestPath !== null}
                      onCheckedChange={(checked) =>
                        checked === true ? void chooseRequest() : setRequestPath(null)
                      }
                    />
                    <span>
                      <span className="block">{t.ownKey}</span>
                      <span className="block text-xs text-muted-foreground">{t.ownKeyHint}</span>
                    </span>
                  </label>
                  {requestPath !== null && (
                    <p className="mt-1.5 ml-[23px] flex items-center gap-2 text-xs">
                      <FileText className="size-3.5 shrink-0 text-muted-foreground" />
                      <span className="selectable truncate" title={requestPath}>
                        {requestPath.split("/").pop()}
                      </span>
                      <button
                        type="button"
                        onClick={() => void chooseRequest()}
                        className="shrink-0 rounded-sm text-primary outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50"
                      >
                        {t.requestChange}
                      </button>
                    </p>
                  )}
                </div>

                <Field label={t.files.title}>
                  <FilesChoice
                    value={files}
                    onChange={setFiles}
                    withKey={requestPath === null}
                    chain={role === "issuing"}
                  />
                </Field>

                {needsPassword && (
                  <div className="grid grid-cols-2 gap-3">
                    <Field label={t.p12Password}>
                      <SecretInput
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        inputClassName={fieldHeight}
                      />
                    </Field>
                    <Field label={t.p12PasswordRepeat}>
                      <SecretInput
                        value={passwordRepeat}
                        onChange={(event) => setPasswordRepeat(event.target.value)}
                        aria-invalid={passwordRepeat !== "" && password !== passwordRepeat}
                        inputClassName={fieldHeight}
                      />
                    </Field>
                    <p className="col-span-2 -mt-1 text-xs text-muted-foreground">
                      {passwordRepeat !== "" && password !== passwordRepeat ? (
                        <span className="text-destructive">{t.passwordsDiffer}</span>
                      ) : (
                        t.p12PasswordHint
                      )}
                    </p>
                  </div>
                )}

                {/* Without an issuing CA the root signs anyway. */}
                {isServer(profile) && pki.issuing !== null && (
                  <label className="flex items-start gap-2.5">
                    <Checkbox
                      className="mt-0.5"
                      checked={signWithRoot}
                      onCheckedChange={(checked) => setSignWithRoot(checked === true)}
                    />
                    <span>
                      <span className="block">{t.noChain}</span>
                      <span className="block text-xs text-muted-foreground">{t.noChainHint}</span>
                    </span>
                  </label>
                )}
              </>
            )}

            {needsOpens && (
              <Field label={t.repack.opens} hint={t.renewOpensHint}>
                <SecretInput
                  // A renewal has no names to type: this is the first field.
                  ref={task.kind === "renew" ? firstField : undefined}
                  value={opens}
                  onChange={(event) => setOpens(event.target.value)}
                  className="w-64"
                  inputClassName={fieldHeight}
                />
              </Field>
            )}

            {canRevokeOld && (
              <label className="flex items-start gap-2.5">
                <Checkbox
                  className="mt-0.5"
                  checked={revokeOld}
                  onCheckedChange={(checked) => setRevokeOld(checked === true)}
                />
                <span>
                  <span className="block">{t.revokeOld}</span>
                  <span className="block text-xs text-muted-foreground">{t.revokeOldHint}</span>
                </span>
              </label>
            )}

            <div>
              <button
                type="button"
                aria-expanded={showOptions}
                onClick={() => setShowOptions(!showOptions)}
                className="flex w-full items-center gap-1.5 rounded-sm text-left text-sm text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
              >
                <ChevronRight
                  className={cn("size-3.5 transition-transform", showOptions && "rotate-90")}
                />
                <span className="font-medium">{t.options}</span>
                {/* Folded up, the line still says what will be done. */}
                {!showOptions && (
                  <span className="truncate">
                    {[
                      days === null ? t.validityLongest : t.validityDays(days),
                      makesKey && t.keyKindChoice[keyKind],
                      needsPassword && p12Compatible && t.p12Compatible,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                )}
              </button>
              {showOptions && (
                <div className="mt-3 ml-1.5 flex flex-col gap-4 border-l pl-4">
                  <OptionRow
                    label={t.validity}
                    hint={
                      profile === "tls-server"
                        ? t.validityHintServer
                        : signer
                          ? t.validityHintOther(formatDate(signer.notAfter))
                          : undefined
                    }
                  >
                    <Segmented
                      label={t.validity}
                      options={validityChoices(profile, days).map((choice) => ({
                        value: choice,
                        label: choice === null ? t.validityLongest : t.validityDays(choice),
                      }))}
                      value={days}
                      onChange={setDays}
                    />
                  </OptionRow>
                  {makesKey && (
                    <OptionRow label={t.keyKind} hint={t.keyKindHint}>
                      <Segmented
                        label={t.keyKind}
                        options={keyKinds.map((kind) => ({
                          value: kind,
                          label: t.keyKindChoice[kind],
                        }))}
                        value={keyKind}
                        onChange={setKeyKind}
                      />
                    </OptionRow>
                  )}
                  {needsPassword && (
                    <label className="flex items-start gap-2.5">
                      <Checkbox
                        className="mt-0.5"
                        checked={p12Compatible}
                        onCheckedChange={(checked) => setP12Compatible(checked === true)}
                      />
                      <span>
                        <span className="block">{t.p12Compatible}</span>
                        <span className="block text-xs text-muted-foreground">
                          {t.p12CompatibleHint}
                        </span>
                      </span>
                    </label>
                  )}
                </div>
              )}
            </div>

            <SignerLine
              role={role}
              pki={pki}
              connected={signerConnected}
              known={devices !== null}
            />
            {error && <ErrorLine>{error}</ErrorLine>}
          </form>
        )}

        {step === "pin" && signer && (
          <form
            id="pin"
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (pin.length >= 6 && signerConnected) void sign();
            }}
          >
            {task.kind === "list" && (
              <>
                <p className="text-sm text-muted-foreground">{t.listAbout(t.roleInText[role])}</p>
                <SignerLine
                  role={role}
                  pki={pki}
                  connected={signerConnected}
                  known={devices !== null}
                />
              </>
            )}
            <Field
              label={
                <>
                  {t.pinOf}
                  <KeyTag serial={signer.yubikey} />
                </>
              }
              hint={t.pinHint}
            >
              <SecretInput
                ref={firstField}
                inputMode="numeric"
                maxLength={8}
                value={pin}
                onChange={(event) => setPin(event.target.value)}
                className="w-44"
                inputClassName={cn("tracking-widest", fieldHeight)}
              />
            </Field>
            {attemptsLeft !== undefined && attemptsLeft < 3 && !error && (
              <p className="text-xs text-amber-700 dark:text-amber-400">
                {t.pinAttempts(attemptsLeft)}
              </p>
            )}
            {error && <ErrorLine>{error}</ErrorLine>}
          </form>
        )}

        {step === "signing" && (
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            {touching ? (
              <>
                <span className="relative flex size-14 items-center justify-center">
                  <span className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
                  <span className="relative flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
                    <Fingerprint className="size-7" strokeWidth={1.5} />
                  </span>
                </span>
                <p className="text-xl font-medium">{t.touchTitle}</p>
                <p className="text-sm text-muted-foreground">{t.touchHint}</p>
              </>
            ) : (
              <>
                <LoaderCircle className="size-7 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">{t.checkingPin}</p>
              </>
            )}
          </div>
        )}

        {step === "done" && outcome && (
          // No wider than the dialog, whatever is in it.
          <div className="flex min-w-0 flex-col gap-3">
            <div className="flex items-center gap-2.5 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-emerald-700 dark:text-emerald-400">
              <Check className="size-4 shrink-0" />
              <span className="selectable min-w-0 font-medium break-words">{outcome.headline}</span>
            </div>
            {outcome.note && <p className="text-sm text-muted-foreground">{outcome.note}</p>}
            <div>
              <p className="mb-1.5 text-xs font-medium text-muted-foreground">{t.doneFiles}</p>
              <ul className="divide-y rounded-lg border">
                {outcome.files.map((file) => (
                  <li key={file.name} className="flex items-start gap-2.5 px-3 py-2">
                    {file.holdsPrivateKey ? (
                      <FileKey2 className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
                    ) : (
                      <FileText className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                    )}
                    <span>
                      <span className="selectable block font-mono text-sm">{file.name}</span>
                      <span className="block text-xs text-muted-foreground">
                        {(outcome.fromRoot ? t.fileFromRoot[file.name] : undefined) ??
                          t.file[file.name] ??
                          ""}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
              {/* Where the files are. The path is as long as the names in it,
                  a group's among them, so it runs on to a second line
                  rather than push the dialog wider than the window. */}
              <p
                className="selectable mt-2 text-xs break-all text-muted-foreground"
                title={outcome.folder}
              >
                {folderShown}
              </p>
            </div>
            {/* The root CA is not among the files: it has one place, and
                the steps for every system are there. */}
            {outcome.trust && onTrust && (
              <p className="flex items-center gap-3 border-t pt-3 text-xs text-muted-foreground">
                <span className="flex-1">{t.trustAfter}</span>
                <Button variant="outline" size="sm" onClick={onTrust}>
                  {t.trust.menu}
                </Button>
              </p>
            )}
          </div>
        )}

        {step !== "kind" && step !== "signing" && (
          <DialogFooter>
            {/* Where a step is the dialog's first, there is nothing to go
                back to; the way out is to cancel. */}
            {step === "details" && (
              <>
                {task.kind === "new" ? (
                  <Button variant="ghost" className="mr-auto" onClick={() => setStep("kind")}>
                    <ArrowLeft />
                    {t.back}
                  </Button>
                ) : (
                  <Button variant="ghost" className="mr-auto" onClick={close}>
                    {t.cancel}
                  </Button>
                )}
                <Button type="submit" form="details" disabled={!detailsOk || !signerConnected}>
                  {t.next}
                </Button>
              </>
            )}
            {step === "pin" && (
              <>
                {task.kind === "list" ? (
                  <Button variant="ghost" className="mr-auto" onClick={close}>
                    {t.cancel}
                  </Button>
                ) : (
                  <Button variant="ghost" className="mr-auto" onClick={() => setStep("details")}>
                    <ArrowLeft />
                    {t.back}
                  </Button>
                )}
                <Button type="submit" form="pin" disabled={pin.length < 6 || !signerConnected}>
                  {task.kind === "list" ? t.sign : t.issue}
                </Button>
              </>
            )}
            {step === "done" && outcome && (
              <>
                <Button
                  variant="outline"
                  // A file inside it, so that Finder opens the folder itself.
                  onClick={() =>
                    void api.reveal(
                      outcome.files.length > 0
                        ? `${outcome.folder}/${outcome.files[0].name}`
                        : outcome.folder,
                    )
                  }
                >
                  {t.showInFinder}
                </Button>
                <Button onClick={close}>{t.done}</Button>
              </>
            )}
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** The height of a text field in this dialog: a pixel more above and below
 *  what is typed than a field has elsewhere, the search over the list
 *  among them. */
const fieldHeight = "h-[30px]";

function Field({
  label,
  hint,
  children,
}: {
  label: React.ReactNode;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/**
 * One of the options, with its name beside its choices instead of above
 * them: unfolded, the options then stay within a small window.
 */
function OptionRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[4.5rem_1fr] items-center gap-x-3 gap-y-1.5">
      <Label>{label}</Label>
      <div>{children}</div>
      {hint && <p className="col-start-2 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function ErrorLine({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" />
      {children}
    </p>
  );
}

/** Which CA will sign, and whether its YubiKey is there to do it. */
function SignerLine({
  role,
  pki,
  connected,
  known,
}: {
  role: CaRole;
  pki: Pki;
  connected: boolean;
  known: boolean;
}) {
  const signer = role === "root" ? pki.root : pki.issuing;
  if (!signer) {
    return <p className="text-xs text-amber-700 dark:text-amber-400">{t.noIssuingYet}</p>;
  }
  return (
    <div className="flex items-center gap-2 rounded-lg bg-muted/60 px-3 py-2">
      <span
        className={cn(
          "size-1.5 shrink-0 rounded-full",
          connected ? "bg-connected" : "bg-amber-500",
        )}
        aria-hidden
      />
      <span>{t.signedBy(`${t.role[role]} “${commonName(signer.subject)}”`)}</span>
      <span className="ml-auto text-muted-foreground">
        {connected || !known ? <KeyName serial={signer.yubikey} /> : t.connectKey(signer.yubikey)}
      </span>
    </div>
  );
}

/** Why a YubiKey did not do what it was asked, in words. */
export function explain(failure: Failure): string {
  switch (failure.kind) {
    case "wrong-pin":
      return failure.serial
        ? t.failure.wrongPinOn(failure.serial, failure.attemptsLeft)
        : t.failure.wrongPin(failure.attemptsLeft);
    case "pin-locked":
      return failure.serial ? t.failure.pinLockedOn(failure.serial) : t.failure.pinLocked;
    case "last-attempt":
      return failure.serial ? t.failure.lastAttemptOn(failure.serial) : t.failure.lastAttempt;
    case "wrong-puk":
      return t.failure.wrongPuk(failure.attemptsLeft);
    case "puk-locked":
      return t.failure.pukLocked;
    case "not-touched":
      return t.failure.notTouched;
    case "key-missing":
      return t.failure.keyMissing;
    case "wrong-password":
      return t.failure.wrongPassword;
    case "interrupted":
      return t.failure.interrupted(failure.message);
    case "other":
      return failure.message;
    default:
      // Something that is not one of ours, such as a lost connection.
      return String((failure as { message?: string })?.message ?? failure);
  }
}
