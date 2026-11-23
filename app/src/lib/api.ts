// Everything the window knows comes through this file. Inside the app it
// talks to the Rust side; in a plain browser, where there is no Rust side,
// it answers with sample data so the interface can be worked on alone.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { documentDir, homeDir, join } from "@tauri-apps/api/path";
import { open, save } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

export type CaRole = "root" | "issuing";
export type Profile = "tls-server" | "tls-client" | "ipsec-gateway" | "ipsec-client";
export type Status = "valid" | "expires-soon" | "expired" | "revoked";

export interface DeviceCa {
  role: CaRole;
  subject: string;
  notAfter: string;
  algorithm: string | null;
  generatedOnDevice: boolean | null;
  touchRequired: boolean | null;
  keyMatchesCertificate: boolean;
  /**
   * For an issuing CA: whether the root in question signed it. That root
   * is the open PKI's, or with no PKI open, the one root CA on a connected
   * YubiKey. `null` for a root CA and when there is no such root.
   */
  signedByRoot: boolean | null;
  /**
   * With a workspace open: whether this is exactly the CA certificate the
   * workspace has for this role. `null` with no workspace open.
   */
  matchesWorkspace: boolean | null;
}

export interface Device {
  serial: number;
  firmware: string;
  pinAttemptsLeft: number;
  factoryCredentials: boolean;
  /** The PIN is the one every YubiKey ships with. */
  factoryPin: boolean;
  /** Slot 9c holds something; a new CA on this key destroys it. */
  slotInUse: boolean;
  /** What it holds is a key without a certificate, left by a CA that was
   *  not finished. */
  keyWithoutCertificate: boolean;
  /** Other PIV slots that hold a certificate, which a reset destroys too. */
  otherSlots: string[];
  ca: DeviceCa | null;
}

export interface Devices {
  usable: Device[];
  unusable: { reader: string; reason: string }[];
}

/** How the revocation list a CA signed last stands. */
export interface Revocation {
  /** Number of that list; `null` if the CA has not signed one yet. */
  number: number | null;
  /** Until when devices treat that list as current. */
  nextUpdate: string | null;
  /** Revoked certificates the list does not name yet. */
  unlisted: number;
  /** An issuing CA that this one took the place of had signed a list, so
   *  devices may be checking lists and want one of this CA too. */
  replacedHadList: boolean;
}

export interface Ca {
  subject: string;
  yubikey: number;
  notAfter: string;
  /** The workspace keeps the YubiKey's statement that the key of this CA
   *  was generated inside it. */
  keyAttested: boolean;
  /** Fingerprints of its certificate, as a device shows them when it asks
   *  whether to trust it. Empty if they could not be worked out. */
  sha256: string;
  sha1: string;
  revocation: Revocation;
}

/**
 * Whether a connected YubiKey holds this CA of the open workspace: the
 * very certificate, where that is known, and otherwise one of the same
 * role and name.
 */
export function holdsCa(device: Device | undefined, role: CaRole, ca: Ca | null): boolean {
  if (!device?.ca || !ca || device.ca.role !== role) return false;
  return device.ca.matchesWorkspace ?? device.ca.subject === ca.subject;
}

export interface Certificate {
  serial: string;
  profile: Profile;
  names: string[];
  issuedBy: CaRole;
  issuedAt: string;
  notAfter: string;
  status: Status;
  revokedAt: string | null;
  replaces: string | null;
  /** The group its owner sorted it into: a customer, a site, whatever
   *  they sort by. `null` for none. */
  group: string | null;
  /**
   * Where the CA that signed it stands: the `current` one, an issuing CA
   * that was `replaced` since, or one that was replaced and `revoked`. A
   * certificate of a replaced CA cannot be revoked on its own. One of a
   * revoked CA shows as revoked without a `revokedAt` of its own.
   */
  issuer: "current" | "replaced" | "revoked";
  /** What to show in Finder to get to its files: the certificate inside
   *  its folder in the workspace. `null` if the folder is gone. */
  location: string | null;
  /** The form its files are in; `null` if its folder holds none. */
  form: Files | null;
  /** Whether its private key is in the workspace. Not for a certificate
   *  of a device's own request, nor for one issued again for a key that
   *  stayed with the certificate before it. */
  hasKey: boolean;
}

/** An issuing CA that was replaced, as when its YubiKey was lost. */
export interface RetiredCa {
  subject: string;
  /** Serial number of its certificate; what revoking it goes by. */
  serial: string;
  notAfter: string;
  /** When the root CA revoked it, if it did. */
  revokedAt: string | null;
}

export interface Pki {
  path: string;
  root: Ca;
  issuing: Ca | null;
  /** Issuing CAs that were replaced, oldest first. */
  retired: RetiredCa[];
  certificates: Certificate[];
}

/**
 * What the upload form of the device asks for, which decides the files a
 * certificate comes as: `fullchain` for a field for the certificate and
 * one for the key (the certificate file holds the intermediate CA too),
 * `separate` for a field each, `p12` for one file with a password.
 */
export type Files = "fullchain" | "separate" | "p12";
/** The kind of private key a new certificate gets. */
export type KeyKind = "rsa" | "ecdsa";

export interface IssueRequest {
  pkiPath: string;
  profile: Profile;
  names: string[];
  files: Files;
  /** Password of the .p12 file; only where everything goes into one. */
  p12Password: string | null;
  /** For a device that cannot handle a certificate chain. */
  signWithRoot: boolean;
  /** Expire after this many days; `null` for as late as possible. */
  days: number | null;
  key: KeyKind;
  /** Encrypt the .p12 file the way older systems need it. */
  p12Compatible: boolean;
  /** The group to sort the certificate into; `null` for none. */
  group: string | null;
  pin: string;
}

export interface Issued {
  serial: string;
  notAfter: string;
  /** The certificate's folder in the workspace. */
  folder: string;
  files: { name: string; holdsPrivateKey: boolean }[];
}

/** One YubiKey and the CA it is to get. */
export interface KeySetup {
  serial: number;
  /** Name of the CA to create. */
  name: string;
  /** The key's PIN; for a key with its factory PIN, the one it is to get. */
  pin: string;
  /** The PUK a key with its factory PIN is to get. */
  newPuk: string | null;
  /** Destroy what slot 9c holds now. */
  replace: boolean;
}

/** One YubiKey that is to hold the whole certificate authority. */
export interface RootAloneSetup {
  key: KeySetup;
  /** Where the workspace folder of the new CA goes. */
  workspacePath: string;
}

export interface IssuingSetup {
  /** The YubiKey with the root CA, which signs the new issuing CA. */
  rootSerial: number;
  rootPin: string;
  key: KeySetup;
  /** Where the workspace folder of the new CA goes. */
  workspacePath: string;
}

/**
 * A new issuing CA for an open workspace: its first, where the root CA
 * signed everything so far, or one in place of the issuing CA it has.
 */
export interface IssuingAddition {
  workspacePath: string;
  /** PIN of the YubiKey with the workspace's root CA, which signs. */
  rootPin: string;
  key: KeySetup;
  /** The workspace has an issuing CA, and this one takes its place. */
  replacing: boolean;
  /** Have the root CA revoke the replaced one: its YubiKey was stolen. */
  revokeReplaced: boolean;
}

/** Signing the request a device made for its own key. */
export interface SignRequest {
  pkiPath: string;
  /** The request file (CSR) the device made. */
  csrPath: string;
  profile: Profile;
  names: string[];
  /** Never `p12`: the key stays in the device. */
  files: Files;
  signWithRoot: boolean;
  /** Expire after this many days; `null` for as late as possible. */
  days: number | null;
  /** The group to sort the certificate into; `null` for none. */
  group: string | null;
  pin: string;
}

/** Writing a certificate's files again in another form. */
export interface RepackageRequest {
  path: string;
  serial: string;
  files: Files;
  /** The password of the .p12 file the folder holds now, where the key
   *  is inside it; otherwise `null`. */
  opens: string | null;
  /** The password for the .p12 file to write; otherwise `null`. */
  p12Password: string | null;
  p12Compatible: boolean;
}

export interface Repackaged {
  /** The certificate's folder in the workspace. */
  folder: string;
  /** What it holds now. */
  files: Issued["files"];
  /** The workspace as it is afterwards. */
  pki: Pki;
}

export interface ReissueRequest {
  pkiPath: string;
  /** Serial number of the certificate to replace. */
  serial: string;
  /** The new names; empty keeps them as they are. */
  names: string[];
  /** Mark the replaced certificate as revoked. */
  revokeOld: boolean;
  /** Expire after this many days; `null` for as late as possible. */
  days: number | null;
  /** The password of the `.p12` file the old certificate is in, where it
   *  is in one; the new file gets the same password. */
  opens: string | null;
  pin: string;
}

export interface ListRequest {
  pkiPath: string;
  /** Whose list: each CA lists the certificates it issued itself. */
  role: CaRole;
  pin: string;
}

export interface ListSigned {
  number: number;
  /** How many certificates the list names. */
  count: number;
  nextUpdate: string;
  folder: string;
  files: Issued["files"];
}

/** Why nothing was issued. */
export type Failure =
  // `serial` names the YubiKey where two were asked for their PINs.
  | { kind: "wrong-pin"; attemptsLeft: number; serial?: number | null }
  | { kind: "pin-locked"; serial?: number | null }
  | { kind: "last-attempt"; serial?: number | null }
  | { kind: "wrong-puk"; attemptsLeft: number }
  | { kind: "puk-locked" }
  | { kind: "not-touched" }
  | { kind: "key-missing"; role: CaRole }
  /** The password does not open the `.p12` file the private key is in. */
  | { kind: "wrong-password" }
  /** A new CA key was made but the CA not finished; retrying replaces it.
   *  `notTouched` says that what it lacked was the touch for its signature. */
  | { kind: "interrupted"; message: string; notTouched: boolean }
  | { kind: "other"; message: string };

/** Whether this is the real app rather than a browser preview. */
export const inApp = "__TAURI_INTERNALS__" in window;

/**
 * What a program working on the person's behalf, such as an AI agent, asks
 * the window to put before them: whatever takes a PIN and a touch, or
 * destroys something. The program never does these itself.
 */
export type AgentAsk =
  | {
      kind: "issue";
      profile: Profile;
      names: string[];
      files: Files;
      days: number | null;
      key: KeyKind;
      p12Compatible: boolean;
      signWithRoot: boolean;
      group: string | null;
    }
  | {
      kind: "sign-request";
      csrPath: string;
      profile: Profile;
      /** None means the names the device asked for. */
      names: string[];
      files: Files;
      days: number | null;
      signWithRoot: boolean;
      group: string | null;
    }
  | {
      kind: "reissue";
      serial: string;
      /** None keeps the names as they are. */
      names: string[];
      days: number | null;
      revokeOld: boolean;
    }
  | { kind: "sign-list"; role: CaRole }
  | { kind: "delete"; serial: string }
  /** The wizard for a new certificate authority, or for an issuing CA of
   *  the open workspace. */
  | { kind: "setup"; issuing: boolean };

export interface AgentRequest {
  id: string;
  /** Who asks, as the program called itself. A claim, not a proof. */
  from: string;
  /** The workspace it is about; `null` for the one that is open. */
  workspace: string | null;
  ask: AgentAsk;
}

/** What the window says to a request: first that it waits its turn or is
 *  shown, then how it ended. */
export type AgentReply =
  | { state: "queued" }
  | { state: "shown" }
  | { state: "done"; result: unknown }
  | { state: "declined" }
  | { state: "failed"; message: string };

/** Runs a command that has a YubiKey sign; `onTouch` is called once the
 *  key has taken the PIN and waits to be touched. */
async function signing<T>(
  command: string,
  request: unknown,
  onTouch: () => void,
  argument = "request",
): Promise<T> {
  const stopListening = await listen("yca://touch", onTouch);
  try {
    return await invoke<T>(command, { [argument]: request });
  } finally {
    stopListening();
  }
}

export const api = {
  /**
   * The connected YubiKeys. `pkiPath` is the open PKI folder, if any;
   * issuing CAs are checked against its root.
   */
  devices: (pkiPath: string | null): Promise<Devices> =>
    inApp ? invoke("devices", { pkiPath }) : sample.devices(),
  openPki: (path: string): Promise<Pki> =>
    inApp ? invoke("open_pki", { path }) : sample.pki(path),
  /**
   * Has `handler` called with every request a program makes on the
   * person's behalf, from now on, and `gone` with the id of a request
   * whose program went away before it was answered. Resolves to what
   * stops both.
   */
  onAgentRequest: async (
    handler: (request: AgentRequest) => void,
    gone: (id: string) => void,
  ): Promise<() => void> => {
    if (!inApp) return sample.agentRequests(handler);
    const stopRequests = await listen<AgentRequest>("yca://agent-request", (event) =>
      handler(event.payload),
    );
    const stopGone = await listen<string>("yca://agent-gone", (event) => gone(event.payload));
    await invoke("agent_ready");
    return () => {
      stopRequests();
      stopGone();
    };
  },
  /** Tells the program that made a request what became of it. */
  answerAgent: (id: string, reply: AgentReply): Promise<void> =>
    inApp ? invoke("answer_agent", { id, reply }) : sample.agentAnswer(id, reply),
  /**
   * Something that changes whenever any program writes the workspace;
   * `null` if the folder is gone.
   */
  workspaceStamp: (path: string): Promise<string | null> =>
    inApp ? invoke("workspace_stamp", { path }) : Promise.resolve("preview"),
  /**
   * Where the root CA certificate is as a file to install on devices that
   * are to trust this CA. It is written first if the workspace lacks it.
   */
  rootForDevices: (path: string): Promise<string> =>
    inApp ? invoke("root_for_devices", { path }) : Promise.resolve(`${path}/Home Root CA.crt`),
  /**
   * Issues a certificate. `onTouch` is called once the YubiKey has taken
   * the PIN and waits to be touched. Rejects with a {@link Failure}.
   */
  issue: (request: IssueRequest, onTouch: () => void): Promise<Issued> =>
    inApp ? signing("issue_certificate", request, onTouch) : sample.issue(request, onTouch),
  /**
   * Issues a new certificate for the key of an existing one, to renew it
   * or change its names. Rejects with a {@link Failure}.
   */
  reissue: (request: ReissueRequest, onTouch: () => void): Promise<Issued> =>
    inApp ? signing("reissue_certificate", request, onTouch) : sample.reissue(request, onTouch),
  /**
   * Creates a root CA on a YubiKey. WRITES TO THE YUBIKEY. `onTouch` is
   * called when the key is about to wait for a touch. Rejects with a
   * {@link Failure}.
   */
  createRoot: (key: KeySetup, onTouch: () => void): Promise<{ notAfter: string }> =>
    inApp ? signing("create_root", key, onTouch, "key") : sample.createRoot(key, onTouch),
  /**
   * Creates a root CA on a YubiKey and starts a workspace folder with that
   * root alone, which then signs every certificate. WRITES TO THE YUBIKEY.
   * Rejects with a {@link Failure}.
   */
  createRootAlone: (request: RootAloneSetup, onTouch: () => void): Promise<Pki> =>
    inApp
      ? signing("create_root_alone", request, onTouch)
      : sample.createRootAlone(request, onTouch),
  /**
   * Creates the issuing CA on a second YubiKey, signed by the root, and
   * starts the workspace folder. WRITES TO THE YUBIKEY. Rejects with a
   * {@link Failure}.
   */
  createIssuing: (request: IssuingSetup, onTouch: () => void): Promise<Pki> =>
    inApp ? signing("create_issuing", request, onTouch) : sample.createIssuing(request, onTouch),
  /**
   * Creates an issuing CA on another YubiKey, signed by the root CA of an
   * open workspace, and enters it there: as its first, or in place of the
   * one it has. WRITES TO THE YUBIKEY. Rejects with a {@link Failure}.
   */
  addIssuing: (request: IssuingAddition, onTouch: () => void): Promise<Pki> =>
    inApp ? signing("add_issuing", request, onTouch) : sample.addIssuing(request, onTouch),
  /** Lets the user pick a device's request file; `null` if they cancel. */
  pickRequestFile: async (title: string): Promise<string | null> => {
    if (!inApp) return "/Users/demo/Downloads/switch.csr";
    const picked = await open({
      title,
      multiple: false,
      filters: [{ name: "Certificate request", extensions: ["csr", "req", "pem", "p10", "txt"] }],
    });
    return typeof picked === "string" ? picked : null;
  },
  /** What a device's request asks for. Rejects if the file is no request. */
  readRequest: (path: string): Promise<{ names: string[] }> =>
    inApp ? invoke("read_request", { path }) : sample.readRequest(),
  /**
   * Issues a certificate for the key in a device's request. Rejects with
   * a {@link Failure}.
   */
  signRequest: (request: SignRequest, onTouch: () => void): Promise<Issued> =>
    inApp ? signing("sign_request", request, onTouch) : sample.signRequest(request, onTouch),
  /**
   * Writes the files of a certificate again in another form. Nothing is
   * issued and no YubiKey is needed. Rejects with what went wrong, a
   * wrong password of the .p12 file among it.
   */
  repackage: (request: RepackageRequest): Promise<Repackaged> =>
    inApp ? invoke("repackage_certificate", { request }) : sample.repackage(request),
  /** Marks a certificate as revoked. Needs no YubiKey. */
  revoke: (path: string, serial: string): Promise<Pki> =>
    inApp ? invoke("revoke_certificate", { path, serial }) : sample.revoke(path, serial),
  /**
   * Deletes a certificate from the list. Needs no YubiKey. One that was
   * revoked stays on the revocation list until it would have expired.
   */
  deleteCertificate: (path: string, serial: string): Promise<Pki> =>
    inApp ? invoke("delete_certificate", { path, serial }) : sample.delete(path, serial),
  /**
   * Sorts certificates into a group, or with `null` takes them out of
   * theirs. Needs no YubiKey. Their folders in the workspace move along.
   */
  setGroup: (path: string, serials: string[], group: string | null): Promise<Pki> =>
    inApp ? invoke("set_group", { path, serials, group }) : sample.setGroup(path, serials, group),
  /**
   * Marks a replaced issuing CA as revoked. Needs no YubiKey; devices
   * learn of it from the next revocation list of the root CA.
   */
  revokeReplacedCa: (path: string, serial: string): Promise<Pki> =>
    inApp ? invoke("revoke_replaced_ca", { path, serial }) : sample.revokeReplacedCa(path, serial),
  /** Signs the revocation list of one CA. Rejects with a {@link Failure}. */
  signRevocationList: (request: ListRequest, onTouch: () => void): Promise<ListSigned> =>
    inApp ? signing("sign_revocation_list", request, onTouch) : sample.signList(request, onTouch),
  /**
   * Gives a YubiKey that still has its factory PIN a PIN and a PUK of the
   * user's own. WRITES TO THE YUBIKEY, but leaves its CA alone. Rejects
   * with a {@link Failure}.
   */
  protectKey: (request: { serial: number; newPin: string; newPuk: string }): Promise<void> =>
    inApp ? invoke("protect_key", { request }) : sample.protectKey(request),
  /**
   * Changes the PIN of a YubiKey. WRITES TO THE YUBIKEY, but only the PIN.
   * Rejects with a {@link Failure}.
   */
  changePin: (request: { serial: number; currentPin: string; newPin: string }): Promise<void> =>
    inApp ? invoke("change_key_pin", { request }) : sample.changePin(request),
  /**
   * Sets a new PIN with the PUK. WRITES TO THE YUBIKEY, but only the PIN.
   * Rejects with a {@link Failure}.
   */
  unblockPin: (request: { serial: number; puk: string; newPin: string }): Promise<void> =>
    inApp ? invoke("unblock_key_pin", { request }) : sample.unblockPin(request),
  /**
   * Resets the PIV application of a YubiKey to its factory state.
   * DESTROYS every PIV key and certificate on it. Rejects with a
   * {@link Failure}.
   */
  resetKey: (serial: number): Promise<void> =>
    inApp ? invoke("reset_key", { serial }) : sample.resetKey(serial),
  /** Shows a file or folder in Finder. */
  reveal: async (path: string): Promise<void> => {
    if (inApp) await revealItemInDir(path);
  },
  /**
   * Starts a PKI folder at `path` from the CAs on the connected YubiKeys.
   * Reads the keys only; no PIN.
   */
  adoptPki: (path: string): Promise<Pki> =>
    inApp ? invoke("adopt_pki", { path }) : sample.adopt(path),
  /** Adds the issuing CA from a connected YubiKey to an open PKI. */
  adoptIssuing: (path: string): Promise<Pki> =>
    inApp ? invoke("adopt_issuing", { path }) : sample.adoptIssuing(path),
  /**
   * Lets the user say where a new PKI folder should go, suggesting
   * Documents and `name`; resolves to `null` if they cancel.
   */
  pickNewFolder: async (title: string, name: string): Promise<string | null> => {
    if (!inApp) return `/Users/demo/Documents/${name}`;
    return save({ title, defaultPath: await join(await documentDir(), name) });
  },
  /** The user's home folder, without a slash at its end. */
  homeDir: async (): Promise<string> =>
    inApp ? (await homeDir()).replace(/\/+$/, "") : "/Users/demo",
  /** Lets the user pick a folder; resolves to `null` if they cancel. */
  pickFolder: async (): Promise<string | null> => {
    if (!inApp) return previewWorkspace;
    const picked = await open({ directory: true, multiple: false });
    return typeof picked === "string" ? picked : null;
  },
};

// ---------------------------------------------------------------------------
// Sample data for the browser preview.

// The sample workspace, and where a certificate's folder is in it.
const previewWorkspace = "/Users/demo/Documents/Home Root CA workspace";
const sampleFolder = (workspace: string, name: string, group: string | null = null) =>
  `${workspace}/certificates/${group === null ? "" : `${group}/`}${name.replace(/[^\p{L}\p{N}\-_.@]/gu, "_")}`;

const day = 24 * 60 * 60 * 1000;
const fromNow = (days: number) => new Date(Date.now() + days * day).toISOString();

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** How long the sample CA makes a certificate valid, in days. */
const sampleValidity = (profile: Profile, days: number | null) =>
  Math.min(days ?? Infinity, profile === "tls-server" ? 825 : 3600);
// The sample register, made on first use: empty for a workspace that was
// just started from YubiKeys, filled with earlier certificates otherwise.
let previewRegister: Certificate[] | null = null;
const register = (): Certificate[] => (previewRegister ??= previewAdopted ? [] : earlier());
// What the sample's last revocation lists name, and their numbers.
const previewListed = new Set<string>(["c41d77aa".padEnd(32, "0")]);
// Revoked certificates deleted from the sample register: still to be named.
const previewDeletedRevoked: { serial: string; issuedBy: CaRole }[] = [];
// Both CAs of the sample have signed a list, as a CA in use would have.
const previewListNumber: Record<CaRole, number> = { issuing: 1, root: 1 };

/** Pretends to be a YubiKey: the PIN 000000 is wrong, 111111 is never
 *  touched, anything else works. */
async function pretendKey(pin: string, onTouch: () => void): Promise<void> {
  await pause(500);
  if (pin === "000000") throw { kind: "wrong-pin", attemptsLeft: 2 } satisfies Failure;
  onTouch();
  await pause(pin === "111111" ? 2500 : 1800);
  if (pin === "111111") throw { kind: "not-touched" } satisfies Failure;
}

// YubiKeys of the sample that were left with a key and no certificate, by
// a CA whose signature was never touched for.
const previewUnfinished = new Set<number>();

/** Pretends to put a CA on a YubiKey, and answers as the real thing does:
 *  the PIN 000000 is wrong; the key is made before a touch is asked for;
 *  with the PIN 111111 the first touch never comes, which leaves the key
 *  behind without a certificate; and such a key is in the way until the
 *  next try says it may be replaced. */
async function pretendNewCa(key: KeySetup, onTouch: () => void): Promise<void> {
  await pause(500);
  if (key.pin === "000000") throw { kind: "wrong-pin", attemptsLeft: 2 } satisfies Failure;
  const leftBehind = previewUnfinished.has(key.serial);
  if (leftBehind && !key.replace) {
    throw { kind: "other", message: "slot 9c of this YubiKey is already in use" } satisfies Failure;
  }
  await pause(900);
  onTouch();
  const untouched = key.pin === "111111" && !leftBehind;
  await pause(untouched ? 2500 : 1800);
  if (untouched) {
    previewUnfinished.add(key.serial);
    throw {
      kind: "interrupted",
      message: "the YubiKey did not sign; it was probably not touched in time",
      notTouched: true,
    } satisfies Failure;
  }
  previewUnfinished.delete(key.serial);
}

/** What the sample's next revocation list of a CA has to name. */
function sampleRevoked(role: CaRole): { serial: string }[] {
  const certificates: { serial: string; issuedBy: CaRole }[] = [
    // A certificate of a replaced issuing CA is nobody's to list.
    ...register().filter((c) => c.revokedAt !== null && c.issuer === "current"),
    ...previewDeletedRevoked,
  ];
  return [
    ...certificates.filter((c) => c.issuedBy === role),
    // The root CA's list names the issuing CAs it revoked.
    ...(role === "root" ? previewRetired.filter((ca) => ca.revokedAt !== null) : []),
  ];
}

function sampleRevocation(role: CaRole): Revocation {
  const revoked = sampleRevoked(role);
  const number = previewListNumber[role];
  return {
    number: number || null,
    nextUpdate: number ? fromNow(330) : null,
    unlisted: revoked.filter((c) => !previewListed.has(c.serial)).length,
    replacedHadList: role === "issuing" && previewReplacedHadList,
  };
}
// The sample's issuing CA was replaced after it had signed a list.
let previewReplacedHadList = false;
let previewHasPki = false;
let previewAdopted = false;
let previewIssuingKnown = true;
// The sample's issuing CA, which a replacement puts on another YubiKey.
let previewIssuingCa = { name: "Home Issuing CA", yubikey: 20000002 };
const previewRetired: RetiredCa[] = [];
// YubiKeys of the sample that were given a PIN of their own.
const previewProtected = new Set<number>();
// YubiKeys of the sample that were reset to their factory state.
const previewReset = new Set<number>();
// The sample authority was made on one YubiKey: its root stays plugged in.
let previewAlone = false;

// What is plugged in before a PKI is open, chosen in the address bar:
// `?keys=stranger` is a root with the issuing CA of some other PKI,
// `?keys=root` the root alone, `?keys=roots` two roots, `?keys=new` two
// YubiKeys fresh from the box; anything else is a root with its own
// issuing CA. `?keys=odd` is that too, with what a CA taken over from
// another tool may bring: an issuing YubiKey that still has its factory
// PIN, and a root CA whose key was imported rather than made inside. `?keys=lost` is that too, until the PKI is open: then the
// issuing YubiKey is gone, and the root is out of the safe with a new
// YubiKey beside it, to try replacing the issuing CA.
const previewKeys = new URLSearchParams(window.location.search).get("keys");

const sampleKey = (
  serial: number,
  role: CaRole,
  name: string,
  days: number,
  signedByRoot: boolean | null = role === "issuing" ? true : null,
): Device => ({
  serial,
  firmware: "5.7.4",
  pinAttemptsLeft: 3,
  factoryCredentials: false,
  factoryPin: false,
  slotInUse: true,
  keyWithoutCertificate: false,
  otherSlots: [],
  ca: {
    role,
    subject: `CN=${name}`,
    notAfter: fromNow(days),
    algorithm: "ECC P-384",
    generatedOnDevice: true,
    touchRequired: true,
    keyMatchesCertificate: true,
    signedByRoot,
    matchesWorkspace: previewHasPki ? true : null,
  },
});

const sample = {
  issue: async (request: IssueRequest, onTouch: () => void): Promise<Issued> => {
    await pretendKey(request.pin, onTouch);
    const expiresIn = sampleValidity(request.profile, request.days);
    const serial = Math.random().toString(16).slice(2, 10);
    register().unshift(
      certificate(serial, request.profile, request.names, 0, expiresIn, {
        issuedBy: request.signWithRoot ? "root" : "issuing",
        group: request.group,
        form: request.files,
      }),
    );
    return {
      serial: serial.padEnd(32, "0"),
      notAfter: fromNow(expiresIn),
      folder: sampleFolder(request.pkiPath, request.names[0], request.group),
      files: sampleFiles(request.files, true, request.signWithRoot),
    };
  },
  repackage: async (request: RepackageRequest): Promise<Repackaged> => {
    await new Promise((resolve) => window.setTimeout(resolve, 300));
    const found = register().find((c) => c.serial === request.serial)!;
    // The pretend .p12 opens with anything but "wrong".
    if (found.form === "p12" && request.opens === "wrong") {
      throw "the password does not open the .p12 file";
    }
    found.form = request.files;
    return {
      folder: sampleFolder(request.path, found.names[0], found.group),
      files: sampleFiles(request.files, found.hasKey, found.issuedBy === "root"),
      pki: await sample.pki(request.path),
    };
  },
  createRoot: async (key: KeySetup, onTouch: () => void): Promise<{ notAfter: string }> => {
    await pretendNewCa(key, onTouch);
    return { notAfter: fromNow(7305) };
  },
  createRootAlone: async (request: RootAloneSetup, onTouch: () => void): Promise<Pki> => {
    await pretendNewCa(request.key, onTouch);
    previewAdopted = true;
    previewIssuingKnown = false;
    previewAlone = true;
    return sample.pki(request.workspacePath);
  },
  createIssuing: async (request: IssuingSetup, onTouch: () => void): Promise<Pki> => {
    await pretendNewCa(request.key, onTouch);
    previewAdopted = true;
    previewIssuingKnown = true;
    return sample.pki(request.workspacePath);
  },
  addIssuing: async (request: IssuingAddition, onTouch: () => void): Promise<Pki> => {
    // The root is asked first, and says so when it refuses.
    if (request.rootPin === "000000") {
      await pause(500);
      throw { kind: "wrong-pin", attemptsLeft: 2, serial: 20000001 } satisfies Failure;
    }
    await pretendNewCa(request.key, onTouch);
    if (request.replacing) {
      // The old CA's list goes with it; the new one has none yet.
      previewReplacedHadList ||= previewListNumber.issuing > 0;
      previewListNumber.issuing = 0;
      const revokedAt = request.revokeReplaced ? new Date().toISOString() : null;
      previewRetired.push({
        subject: `CN=${previewIssuingCa.name}`,
        serial: `ca${previewRetired.length}`.padEnd(32, "0"),
        notAfter: fromNow(3600),
        revokedAt,
      });
      // What the old CA still had to list is nobody's to list any more.
      for (let i = previewDeletedRevoked.length - 1; i >= 0; i -= 1) {
        if (previewDeletedRevoked[i].issuedBy === "issuing") previewDeletedRevoked.splice(i, 1);
      }
      for (const entry of register()) {
        if (entry.issuedBy !== "issuing" || entry.issuer !== "current") continue;
        entry.issuer = revokedAt ? "revoked" : "replaced";
        if (revokedAt && (entry.status === "valid" || entry.status === "expires-soon")) {
          entry.status = "revoked";
        }
      }
    }
    previewIssuingCa = { name: request.key.name, yubikey: request.key.serial };
    previewIssuingKnown = true;
    previewAlone = false;
    return sample.pki(request.workspacePath);
  },
  protectKey: async (request: { serial: number; newPin: string }): Promise<void> => {
    await pause(800);
    if (request.newPin === "123456") {
      throw { kind: "other", message: "the new PIN must differ from the factory one" };
    }
    previewProtected.add(request.serial);
  },
  changePin: async (request: { currentPin: string }): Promise<void> => {
    await pause(800);
    if (request.currentPin === "000000") {
      throw { kind: "wrong-pin", attemptsLeft: 2 } satisfies Failure;
    }
  },
  unblockPin: async (request: { puk: string }): Promise<void> => {
    await pause(800);
    if (request.puk === "00000000") {
      throw { kind: "wrong-puk", attemptsLeft: 2 } satisfies Failure;
    }
  },
  resetKey: async (serial: number): Promise<void> => {
    await pause(1200);
    previewReset.add(serial);
  },
  revokeReplacedCa: async (path: string, serial: string): Promise<Pki> => {
    previewRetired.find((ca) => ca.serial === serial)!.revokedAt = new Date().toISOString();
    for (const entry of register()) {
      if (entry.issuer !== "replaced") continue;
      entry.issuer = "revoked";
      if (entry.status === "valid" || entry.status === "expires-soon") entry.status = "revoked";
    }
    return sample.pki(path);
  },
  readRequest: async (): Promise<{ names: string[] }> => ({
    names: ["switch.home.example", "192.168.1.30"],
  }),
  // `?ask=issue`, `reissue`, `list`, `delete`, `request` or `setup` in the
  // address has a program ask for that a moment after the page is up.
  agentRequests: (handler: (request: AgentRequest) => void): (() => void) => {
    const kind = new URLSearchParams(window.location.search).get("ask");
    const asks: Record<string, AgentAsk> = {
      issue: {
        kind: "issue",
        profile: "tls-server",
        names: ["camera.home.example", "192.168.1.40"],
        files: "separate",
        days: 180,
        key: "ecdsa",
        p12Compatible: false,
        signWithRoot: false,
        group: "Network",
      },
      request: {
        kind: "sign-request",
        csrPath: "/Users/demo/Downloads/switch.csr",
        profile: "tls-server",
        names: [],
        files: "fullchain",
        days: null,
        signWithRoot: false,
        group: null,
      },
      reissue: {
        kind: "reissue",
        serial: "5d20be77",
        names: [],
        days: null,
        revokeOld: false,
      },
      list: { kind: "sign-list", role: "issuing" },
      delete: { kind: "delete", serial: "19bb6c03" },
      setup: { kind: "setup", issuing: false },
    };
    // Several, separated by commas, come one right after the other.
    const wanted = (kind ?? "").split(",").flatMap((name) => (asks[name] ? [asks[name]] : []));
    const timer = window.setTimeout(
      () =>
        wanted.forEach((ask, index) =>
          handler({ id: `preview-${index + 1}`, from: "Claude Code", workspace: null, ask }),
        ),
      800,
    );
    return () => window.clearTimeout(timer);
  },
  agentAnswer: async (id: string, reply: AgentReply): Promise<void> => {
    console.info("answer to the program", id, JSON.stringify(reply));
  },
  signRequest: async (request: SignRequest, onTouch: () => void): Promise<Issued> => {
    await pretendKey(request.pin, onTouch);
    const expiresIn = sampleValidity(request.profile, request.days);
    const serial = Math.random().toString(16).slice(2, 10);
    register().unshift(
      certificate(serial, request.profile, request.names, 0, expiresIn, {
        issuedBy: request.signWithRoot ? "root" : "issuing",
        group: request.group,
        form: request.files,
        hasKey: false,
      }),
    );
    return {
      serial: serial.padEnd(32, "0"),
      notAfter: fromNow(expiresIn),
      folder: sampleFolder(request.pkiPath, request.names[0], request.group),
      files: sampleFiles(request.files, false, request.signWithRoot),
    };
  },
  reissue: async (request: ReissueRequest, onTouch: () => void): Promise<Issued> => {
    const old = register().find((c) => c.serial === request.serial)!;
    // The pretend .p12 opens with anything but "wrong", and is tried
    // before the YubiKey, as in the app.
    if (old.form === "p12" && old.hasKey && request.opens === "wrong") {
      throw { kind: "wrong-password" } satisfies Failure;
    }
    await pretendKey(request.pin, onTouch);
    const names = request.names.length > 0 ? request.names : old.names;
    const expiresIn = sampleValidity(old.profile, request.days);
    const serial = Math.random().toString(16).slice(2, 10);
    register().unshift(
      certificate(serial, old.profile, names, 0, expiresIn, {
        issuedBy: old.issuedBy,
        replaces: old.serial,
        group: old.group,
        form: old.form ?? "fullchain",
        hasKey: old.hasKey,
      }),
    );
    if (request.revokeOld && (old.status === "valid" || old.status === "expires-soon")) {
      old.status = "revoked";
      old.revokedAt = new Date().toISOString();
    }
    return {
      serial: serial.padEnd(32, "0"),
      notAfter: fromNow(expiresIn),
      folder: sampleFolder(request.pkiPath, names[0]),
      files: sampleFiles(old.form ?? "fullchain", old.hasKey, old.issuedBy === "root"),
    };
  },
  setGroup: async (path: string, serials: string[], group: string | null): Promise<Pki> => {
    const tidy = group?.trim().replace(/\s+/g, " ") || null;
    // The spelling of a group that is there already wins.
    const known = register().find((c) => c.group?.toLowerCase() === tidy?.toLowerCase())?.group;
    for (const entry of register()) {
      if (!serials.includes(entry.serial)) continue;
      entry.group = known ?? tidy;
      entry.location = `${sampleFolder(path, entry.names[0], entry.group)}/fullchain.crt`;
    }
    return sample.pki(path);
  },
  revoke: async (path: string, serial: string): Promise<Pki> => {
    const found = register().find((c) => c.serial === serial)!;
    found.status = "revoked";
    found.revokedAt = new Date().toISOString();
    return sample.pki(path);
  },
  delete: async (path: string, serial: string): Promise<Pki> => {
    const list = register();
    const [gone] = list.splice(
      list.findIndex((c) => c.serial === serial),
      1,
    );
    if (gone.status === "revoked" && new Date(gone.notAfter).getTime() > Date.now()) {
      previewDeletedRevoked.push({ serial: gone.serial, issuedBy: gone.issuedBy });
    }
    return sample.pki(path);
  },
  signList: async (request: ListRequest, onTouch: () => void): Promise<ListSigned> => {
    await pretendKey(request.pin, onTouch);
    const revoked = sampleRevoked(request.role);
    for (const entry of revoked) previewListed.add(entry.serial);
    const number = (previewListNumber[request.role] += 1);
    return {
      number,
      count: revoked.length,
      nextUpdate: fromNow(365),
      folder: `${request.pkiPath}/crl`,
      files: [`${request.role}.crl.pem`, `${request.role}.crl`].map((name) => ({
        name,
        holdsPrivateKey: false,
      })),
    };
  },
  devices: async (): Promise<Devices> => {
    const issuing = sampleKey(previewIssuingCa.yubikey, "issuing", previewIssuingCa.name, 3600);
    const root = sampleKey(20000001, "root", "Home Root CA", 7250);
    // The everyday YubiKey is gone and has not been replaced yet.
    const lost = previewKeys === "lost" && previewIssuingCa.yubikey === 20000002;
    if (previewKeys === "odd") {
      const unprotected = !previewProtected.has(issuing.serial);
      issuing.factoryCredentials = unprotected;
      issuing.factoryPin = unprotected;
      root.ca!.generatedOnDevice = false;
    }
    // Fresh from the box: nothing on it and the PIN everybody knows.
    const fresh = (serial: number): Device => ({
      serial,
      firmware: "5.7.4",
      pinAttemptsLeft: 3,
      factoryCredentials: true,
      factoryPin: true,
      slotInUse: false,
      keyWithoutCertificate: false,
      otherSlots: [],
      ca: null,
    });
    // Given a PIN by then, and left with a key that has no certificate.
    const unfinished = (key: Device): Device => ({
      ...key,
      factoryCredentials: false,
      factoryPin: false,
      slotInUse: true,
      keyWithoutCertificate: true,
      ca: null,
    });
    const before: Record<string, Device[]> = {
      new: [fresh(30000001), fresh(30000002)],
      stranger: [sampleKey(20000003, "issuing", "Lab Issuing CA", 900, false), root],
      root: [root],
      // With two roots there is no telling which one an issuing CA is
      // checked against.
      roots: [
        root,
        sampleKey(20000004, "root", "Lab Root CA", 5000),
        { ...issuing, ca: { ...issuing.ca!, signedByRoot: null } },
      ],
    };
    const connected = previewHasPki
      ? previewAlone || lost
        ? // With a second key at hand, to try adding an issuing CA.
          [root, fresh(30000002)]
        : previewKeys === "lost" || previewKeys === "odd"
          ? [root, issuing]
          : [issuing]
      : (before[previewKeys ?? ""] ?? [root, issuing]);
    return {
      // Once a PKI is open the root is "back in the safe". A key that was
      // reset is as it came out of its box.
      usable: connected.map((key) =>
        previewReset.has(key.serial)
          ? fresh(key.serial)
          : previewUnfinished.has(key.serial)
            ? unfinished(key)
            : key,
      ),
      unusable: [],
    };
  },
  adopt: async (path: string): Promise<Pki> => {
    previewAdopted = true;
    // Started from the root alone, the PKI has no issuing CA until the
    // one on the connected YubiKey is added.
    previewIssuingKnown = previewKeys !== "stranger" && previewKeys !== "root";
    return sample.pki(path);
  },
  adoptIssuing: async (path: string): Promise<Pki> => {
    previewIssuingKnown = true;
    return sample.pki(path);
  },
  pki: async (path: string): Promise<Pki> => {
    previewHasPki = true;
    return {
      path,
      root: {
        subject: "CN=Home Root CA",
        yubikey: 20000001,
        notAfter: fromNow(7250),
        keyAttested: previewKeys !== "odd",
        sha256:
          "3F 9A 21 C4 7E 05 B8 D2 61 0C 94 AF 5B E7 13 88 2D F0 46 9B C1 7A 30 E5 8C 14 D9 62 A7 0B F3 5E",
        sha1: "8B 41 F2 0D 6C A9 37 E4 15 9F 70 C8 2A B6 53 DE 91 04 7C 3B",
        revocation: sampleRevocation("root"),
      },
      issuing: previewIssuingKnown
        ? {
            subject: `CN=${previewIssuingCa.name}`,
            yubikey: previewIssuingCa.yubikey,
            notAfter: fromNow(3600),
            keyAttested: true,
            sha256:
              "A1 5C 08 E3 9D 42 7B F6 20 C7 35 8E D4 19 6A B0 F8 03 5D 92 4E C6 71 2B 89 E0 3A D7 14 6F B5 C2",
            sha1: "2E 97 C0 5A 13 F4 8D 66 B2 09 E1 7C 35 A8 4F D0 9B 21 6E 73",
            revocation: sampleRevocation("issuing"),
          }
        : null,
      retired: previewRetired.map((ca) => ({ ...ca })),
      certificates: register().map((entry) => ({ ...entry })),
    };
  },
};

// `?sample=web` gives the sample PKI certificates for web servers and TLS
// clients only, as the pictures in docs/screenshots show it.
const previewSample = new URLSearchParams(window.location.search).get("sample");

/** What the sample PKI issued before the preview started. */
function earlier(): Certificate[] {
  if (previewSample === "web") return earlierWeb();
  return [
    certificate("a91f03c2", "ipsec-client", ["alice@example.com"], -2, 3600, {
      group: "Family",
      form: "p12",
    }),
    certificate("5d20be77", "tls-server", ["nas.home.example", "192.168.1.20"], -12, 813),
    certificate("77c0a4e1", "ipsec-gateway", ["vpn.home.example"], -40, 3560, { group: "Network" }),
    // Issued again for the key the switch already had.
    certificate("0b3e91d4", "tls-server", ["switch-new.home.example"], -41, 784, {
      replaces: "c41d77aa",
      group: "Network",
      hasKey: false,
    }),
    certificate("c41d77aa", "tls-server", ["switch-old.home.example"], -400, 425, {
      status: "revoked",
      revokedAt: fromNow(-41),
      group: "Network",
    }),
    certificate("e2a8f590", "tls-client", ["backup-agent"], -700, 21, {
      status: "expires-soon",
    }),
    certificate("19bb6c03", "ipsec-client", ["old-phone"], -900, -75, {
      status: "expired",
      group: "Family",
    }),
    // For the printer's own request, and by the root CA because the
    // printer cannot handle a chain: one file, and no other form of it.
    certificate("3f6d2a18", "tls-server", ["printer.home.example"], -300, 525, {
      issuedBy: "root",
      hasKey: false,
    }),
  ];
}

/** The same with SSL/TLS certificates only: every status, groups, one
 *  renewed, one the root signed for a device's own request. */
function earlierWeb(): Certificate[] {
  return [
    certificate("5d20be77", "tls-server", ["nas.home.example", "192.168.1.20"], -12, 813, {
      group: "Home",
    }),
    certificate("3f6d2a18", "tls-server", ["printer.home.example"], -300, 525, {
      issuedBy: "root",
      hasKey: false,
      group: "Home",
    }),
    certificate("6b2f0d91", "tls-server", ["old-camera.home.example"], -900, -75, {
      status: "expired",
      group: "Home",
    }),
    certificate("8a1c55e0", "tls-server", ["router.home.example", "192.168.1.1"], -30, 795, {
      group: "Network",
    }),
    certificate("0b3e91d4", "tls-server", ["switch-new.home.example"], -41, 784, {
      replaces: "c41d77aa",
      group: "Network",
      hasKey: false,
    }),
    certificate("c41d77aa", "tls-server", ["switch-old.home.example"], -400, 425, {
      status: "revoked",
      revokedAt: fromNow(-41),
      group: "Network",
    }),
    certificate("d4e7a3b2", "tls-server", ["grafana.home.example"], -60, 765),
    certificate("e2a8f590", "tls-client", ["backup-agent"], -700, 21, {
      status: "expires-soon",
    }),
  ];
}

function certificate(
  serialStart: string,
  profile: Profile,
  names: string[],
  issuedDaysAgo: number,
  expiresInDays: number,
  extra: Partial<Certificate> = {},
): Certificate {
  return {
    serial: serialStart.padEnd(32, "0"),
    profile,
    names,
    issuedBy: "issuing",
    issuedAt: fromNow(issuedDaysAgo),
    notAfter: fromNow(expiresInDays),
    status: "valid",
    revokedAt: null,
    replaces: null,
    group: null,
    issuer: "current",
    location: `${sampleFolder(previewWorkspace, names[0], extra.group ?? null)}/fullchain.crt`,
    form: "fullchain",
    hasKey: true,
    ...extra,
  };
}

/** The files of a form, as the app writes them. */
function sampleFiles(form: Files, withKey: boolean, signedByRoot: boolean): Issued["files"] {
  const certificates =
    form === "p12"
      ? ["certificate.p12"]
      : signedByRoot
        ? ["certificate.crt"]
        : form === "fullchain"
          ? ["fullchain.crt"]
          : ["certificate.crt", "intermediate-ca.crt"];
  const names = form !== "p12" && withKey ? [...certificates, "private-key.key"] : certificates;
  return names.map((name) => ({
    name,
    holdsPrivateKey: name === "private-key.key" || name.endsWith(".p12"),
  }));
}
