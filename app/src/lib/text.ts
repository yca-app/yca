// Every word the interface shows lives here. The app is in English only.
//
// The folder the app keeps for a CA is its "workspace", or "workspace
// folder" where the place is meant. The word "PKI" is never shown: someone
// who wants a certificate for a switch need not know it.

import type { CaRole, Profile, Status } from "@/lib/api";

export const t = {
  appName: "CA for YubiKey",

  // Getting started
  welcomeTitle: "Your own certificate authority, kept on YubiKeys",
  welcomeBody:
    "The private keys of your CA never leave the YubiKeys. On this Mac the app keeps one workspace folder for it: the CA certificates and every certificate you issue, each with its files.",
  connectedKeys: "Connected YubiKeys",
  noKeysConnected: "No YubiKey connected",
  lookingForKeys: "Looking for YubiKeys…",
  holdsCa: (role: string, name: string) => `${role} “${name}”`,
  adopt: "Start from these YubiKeys",
  adoptRootOnly: "Start from the root CA",
  adoptHint:
    "Creates a workspace folder for this CA, where you choose, and copies both CA certificates into it. Nothing on the YubiKeys changes and no PIN is asked for.",
  adoptHintRootOnly:
    "Creates a workspace folder for this CA, where you choose, and copies the root CA certificate into it. If it has an issuing CA, that can be added later, once its YubiKey is connected. Nothing on the YubiKey changes and no PIN is asked for.",
  // Said where someone decides where the workspace goes.
  workspaceBackup:
    "The workspace will hold every certificate you issue, with its private key. Keep it where only you can read it. The keys of the CA itself are never in it.",
  adoptNeedsRoot: "Connect the YubiKey with the root CA to start from it.",
  // Before any key is there: what connecting one leads to.
  connectToGoOn:
    "Connect your YubiKeys: new ones to make a CA on, or the ones that hold your CA to start a workspace from it.",
  // Under the button that makes a CA, where no connected key holds one.
  createHint: (keys: number) =>
    keys === 1
      ? "Makes a CA on this YubiKey, step by step, and a workspace folder to go with it."
      : "Makes a CA on these YubiKeys, step by step, and a workspace folder to go with it.",
  adoptOneRoot: "More than one root CA is connected. Leave in only the one to start from.",
  leftOut: "Signed by a different root CA. It will be left out.",
  adoptWhere: "Where should the workspace folder go?",
  workspaceFolderName: (rootCa: string) => `${rootCa} workspace`,
  issuingFound: (name: string, serial: number) =>
    `The YubiKey with serial number ${serial} holds “${name}”, signed by this root CA.`,
  adoptIssuing: "Use it as the issuing CA",
  couldNotAdopt: "The workspace folder could not be created",
  openFolder: "Open existing workspace…",
  openAnother: "Open another workspace…",
  workspace: "Workspace",
  workspaceAbout:
    "Everything of this CA on this Mac: its certificates, and a folder for every certificate issued, private key included. Worth backing up, and worth keeping private. The keys of the CA itself are only on the YubiKeys.",
  switchWorkspace: "Switch",
  startFromKeys: "Start from connected YubiKeys…",
  couldNotOpen: "This folder could not be opened",
  workspaceGone: (path: string) => `The workspace folder is not there any more: ${path}`,

  // Creating a new certificate authority
  create: "Create a new certificate authority…",
  createTitle: "New certificate authority",
  createStep: (step: number, of: number) => `Step ${step} of ${of}`,
  createHowMany: "How many YubiKeys will hold it?",
  createTwo: "Two YubiKeys",
  createTwoBadge: "Strongly recommended",
  createTwoAbout:
    "The root CA rests in your safe. The issuing CA, on the second YubiKey, signs from day to day. If the everyday YubiKey is lost or breaks, the root CA makes a new issuing CA and your devices go on trusting it.",
  createOne: "One YubiKey",
  createOneAbout:
    "A single root CA signs every certificate itself. Nothing backs it up: if the YubiKey is lost or breaks, the CA is gone, and every device has to be given a new one.",
  createKeysNote:
    "Either way the keys are made inside the YubiKeys and cannot be copied out, not even for a backup.",
  createAbout:
    "The root CA goes on the YubiKey you keep in a safe. It signs the issuing CA, which goes on the one you use from day to day.",
  createAboutOne: "The root CA goes on your YubiKey and signs every certificate you issue.",
  createName: "Name",
  createRootName: "Home Root CA",
  createAloneName: "Home CA",
  createIssuingName: "Home Issuing CA",
  createKey: "YubiKey",
  createNeedTwo: "Connect both YubiKeys to go on.",
  createTaken: "Chosen for the other CA",
  // Short, beside the key's serial number; in full when pointed at.
  firmware: (version: string) => `fw ${version}`,
  firmwareAbout: (version: string) => `Firmware version ${version}`,
  keyHolds: (role: string, name: string) =>
    `Holds the ${role} “${name}”. It will be destroyed for good.`,
  keyHoldsSomething: "Its CA slot holds something. It will be destroyed for good.",
  keyFresh: "New. You will choose its PIN.",
  keyEmpty: "This YubiKey has an empty CA slot",
  // Followed by the tag with the key's serial number.
  createOn: (role: string, name: string) => `${role} “${name}” on YubiKey`,
  newPin: "New PIN",
  newPinRepeat: "Repeat the PIN",
  newPuk: "New PUK",
  newPukRepeat: "Repeat the PUK",
  newCredentialsHint:
    "6 to 8 characters each. The PIN is asked for with every signature. The PUK unblocks the PIN after three wrong attempts. Write both down: nobody can recover them.",
  credentialLength: "A PIN and a PUK are 6 to 8 characters long.",
  credentialsDiffer: "The two entries differ",
  // Followed by the tag with the key's serial number.
  pinOf: "PIN of YubiKey",
  // Two YubiKeys, two PINs: each field says whose it wants.
  pinOfNewKey: (role: string) => `The YubiKey that gets the new ${role}.`,
  pinOfSigner: "The YubiKey with the root CA, which signs the new one.",
  showSecret: "Show what is typed",
  hideSecret: "Hide what is typed",
  destroyConfirm: (serial: number) =>
    `This cannot be undone. To confirm, type the serial number ${serial}:`,
  createRoot: "Create root CA",
  createIssuing: "Create issuing CA",
  creatingRoot: (serial: number) =>
    `Making the key inside the YubiKey with serial number ${serial}. Touch that YubiKey when it starts to blink.`,
  creatingIssuing: (issuing: number, root: number) =>
    `Making the key inside the YubiKey with serial number ${issuing}. The root CA signs it: touch the YubiKey with serial number ${root} when it starts to blink.`,
  rootDone: (name: string) => `The root CA “${name}” is on its YubiKey.`,
  // Said apart from it: it is what to do now, not what went well, and it
  // says why a PIN is asked for once more. Which PIN depends on whether the
  // second YubiKey is fresh from the box.
  keepRootConnected: (fresh: boolean) =>
    fresh
      ? "Now keep both YubiKeys connected. The second YubiKey gets a PIN and PUK of its own, then the root CA signs the issuing CA."
      : "Now keep both YubiKeys connected. The second YubiKey needs its own PIN, then the root CA signs the issuing CA.",

  // What the wizard says once the YubiKeys have done their part
  finishedStep: "Done",
  finished: {
    created: "Your certificate authority is ready",
    added: "The issuing CA is ready",
    replaced: "The new issuing CA is in place",
  },
  finishedNext: "What next",
  finishedRevoked: (old: string) =>
    `“${old}” is marked as revoked. Devices learn of it from the root CA's revocation list: sign it next, while the root CA's YubiKey is connected.`,
  finishedOldStays: (old: string) =>
    `Certificates signed by “${old}” stay valid. Renewing one has the new issuing CA sign it.`,
  finishedRootRest: (serial: number) =>
    `The issuing CA signs from now on. The YubiKey with the root CA (serial number ${serial}) can go into a safe.`,
  // The same, where the root CA still has a revocation list to sign.
  finishedRootRestAfter: (serial: number) =>
    `After that, the YubiKey with the root CA (serial number ${serial}) can go back into a safe.`,
  finishedAlone:
    "This YubiKey is the whole authority. An issuing CA on a second YubiKey can be added later, in the sidebar.",
  finishedWorkspace: (path: string) =>
    `Everything of this CA is kept in ${path}. Back it up, and keep it private: the keys of the certificates you issue go there too.`,
  finishedTrust:
    "A device trusts your certificates once it trusts the root CA. The root CA's menu in the sidebar has the steps: “Install on your devices…”.",

  // Adding an issuing CA to a workspace whose root CA signs everything
  addIssuing: "Add one on a second YubiKey…",
  addIssuingTitle: "New issuing CA",
  addIssuingAbout: (root: string) =>
    `The issuing CA goes on a second YubiKey, the one you will use from day to day. The root CA “${root}” signs it once and can then rest in a safe. Certificates issued so far stay valid.`,
  holdsWorkspaceRoot: "Holds the root CA of this workspace",
  // Followed by the tag with the key's serial number.
  signedByRootOn: (name: string) => `Signed by the root CA “${name}” on YubiKey`,

  // Replacing the issuing CA, as when its YubiKey is lost
  replaceIssuing: "Replace this issuing CA…",
  replaceIssuingTitle: "Replace the issuing CA",
  replaceIssuingAbout: (root: string, old: string) =>
    `For when the YubiKey with “${old}” is lost, stolen or broken. The root CA “${root}” signs a new issuing CA on another YubiKey. Devices go on trusting the root CA, and certificates issued so far stay valid.`,
  revokeReplaced: "The old YubiKey may be in someone else's hands",
  revokeReplacedHint: (old: string) =>
    `Revokes “${old}” as well. Devices that check the root CA's revocation list then refuse every certificate it signed, so those have to be renewed.`,
  replacedCa: (name: string) => `Replaced: “${name}”`,
  replacedCaValid: "Its certificates stay valid.",
  replacedCaRevoked: (date: string) => `Revoked on ${date}`,
  revokeCa: "Revoke…",
  revokeCaTitle: "Revoke this issuing CA?",
  revokeCaBody:
    "For when its YubiKey may be in someone else's hands. Devices that check the root CA's revocation list will refuse every certificate it signed, so those have to be renewed. It cannot be made valid again. Devices learn of it only from the root CA's revocation list, which you sign afterwards.",

  // What a program asks for on the person's behalf
  agent: {
    asks: (from: string) => `${from} asks for this.`,
    checkSign: "Check it before you sign: nothing is signed without your PIN and your touch.",
    checkDelete: "Check it before you agree.",
    noWorkspace: "No workspace is open in the window; name the workspace folder.",
    noCertificate: (serial: string) =>
      `The workspace has no certificate with the serial number ${serial}, or more than one that begins with it.`,
    revoked: "A revoked certificate is not issued again.",
    noIssuing: "This workspace has no issuing CA.",
  },

  // Groups of certificates
  group: {
    label: "Group",
    none: "No group",
    all: "All groups",
    new: "New group…",
    namePlaceholder: "Name of the group",
    move: "Move to group…",
    moveTitle: "Move to a group",
    moveBody:
      "A group is made by naming it: a customer, a site, whatever you sort by. Leave the name empty to take a certificate out of its group. In the workspace, the certificate's folder moves into the folder of its group.",
    certificates: (count: number) => `${count} certificates`,
    confirmMove: "Move",
    confirmRemove: "Take out of the group",
    selected: (count: number) => `${count} selected`,
    pick: "Move…",
    pickTitle: "Pick certificates and move them into a group",
    pickHint: "Click the certificates to move",
    fold: (name: string) => `Show or hide ${name}`,
  },
  // Writing a certificate's files again, in the form another upload form
  // asks for.
  repack: {
    menu: "Files in another form…",
    title: "Files in another form",
    about:
      "For an upload form that asks for something else. Nothing is issued: it is the same certificate and the same key. The folder then holds the new files and none of the old.",
    noKey:
      "Its private key is not in the workspace, so the files are certificates only and nothing goes into one file.",
    onlyOne:
      "There is one form of files for this certificate and no other: the root CA signed it directly, and its private key is not in the workspace.",
    opens: "Password of the file as it is now",
    opensHint: "The private key is inside that file, and comes out of it with its password.",
    newPassword: "New password for the file",
    confirm: "Write the files",
    done: "The files are written.",
  },
  sortBy: (column: string) => `Sort by ${column.toLowerCase()}`,

  // Making a computer or a phone trust the CA
  trust: {
    menu: "Install on your devices…",
    title: "Make your devices trust this CA",
    about:
      "A computer or phone accepts the certificates you issue once it trusts your root CA. Give it the file below and install it there as a trusted root. Do this only on devices you look after: they will trust everything this CA signs.",
    fileAbout: "The root CA certificate. It is not a secret.",
    fingerprints: "If a device shows a fingerprint when it asks, it should be one of these:",
    sha256: "SHA-256",
    sha1: "SHA-1",
    where: "Where the certificate is being installed",
    platform: {
      macos: "macOS",
      windows: "Windows",
      ios: "iPhone and iPad",
      android: "Android",
    },
    steps: {
      macos: [
        "Open the file. If Keychain Access asks where to add it, choose “login” for yourself or “System” for everyone on the Mac.",
        "In Keychain Access, find the certificate by its name and double-click it.",
        "Open “Trust” and set “When using this certificate” to “Always Trust”.",
        "Close the window and confirm with your password.",
      ],
      windows: [
        "Open the file and click “Install Certificate…”.",
        "Choose “Current User”, or “Local Machine” for everyone on the PC.",
        "Select “Place all certificates in the following store”, click “Browse…” and pick “Trusted Root Certification Authorities”.",
        "Finish, and answer the security warning with “Yes”.",
      ],
      ios: [
        "Send the file to the device, by AirDrop or in an e-mail to yourself, and open it there. The device says that a profile was downloaded.",
        "Open Settings and tap “Profile Downloaded” near the top, or look under General → VPN & Device Management. Tap “Install”.",
        "Go to Settings → General → About → Certificate Trust Settings and switch on full trust for the certificate.",
      ],
      android: [
        "Copy the file to the device.",
        "Open Settings → Security & privacy → More security settings → Encryption & credentials → Install a certificate → CA certificate.",
        "Answer the warning with “Install anyway” and pick the file.",
      ],
    },
    note: {
      macos:
        "Safari, Chrome and most apps go by the keychain. Firefox keeps a list of its own: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.",
      windows:
        "Edge, Chrome and most apps go by this store. Firefox keeps a list of its own: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.",
      ios: "Without the last step the certificate is installed but not trusted, and nothing says so.",
      android:
        "The names differ a little between makers; searching Settings for “certificate” finds the place. Browsers trust a CA installed this way. Other apps decide for themselves, and many do not.",
    },
  },

  // Sidebar
  authorities: "Authorities",
  role: { root: "Root CA", issuing: "Issuing CA" } satisfies Record<CaRole, string>,
  // In the tree of authorities, where there is room for the name devices
  // use for the issuing CA.
  roleInTree: {
    root: "Root CA",
    issuing: "Issuing CA (intermediate)",
  } satisfies Record<CaRole, string>,
  roleHint: {
    root: "Signs the issuing CA. Kept in a safe.",
    issuing: "Signs everyday certificates.",
  } satisfies Record<CaRole, string>,
  noIssuing: "None",
  noIssuingAbout: "The root CA signs certificates itself.",
  validUntil: (date: string) => `Valid until ${date}`,
  keyConnected: "YubiKey connected",
  // Short enough for one line in the narrower card of the issuing CA, next
  // to the serial number.
  keyNotPresent: "YubiKey not present",
  // A YubiKey is told from the others by the serial number printed on it.
  // The number never stands bare: someone new to YubiKeys could take a
  // number next to the word "PIN" for the PIN itself. Where there is a
  // place for it, it is a tag reading "S/N: …" (the KeyTag component);
  // inside a sentence it is spelled out as a serial number.
  yubikey: "YubiKey",
  serialShort: "S/N:",
  serialAbout: "The serial number printed on the YubiKey",
  pinAttempts: (left: number) => (left === 1 ? "1 PIN attempt left" : `${left} PIN attempts left`),
  factoryCredentials: "Factory PIN still in place",
  factoryOther: "Factory PUK or management key still in place",
  setOwnPin: "Change…",
  // A YubiKey's own PIN and PUK, and its reset
  key: {
    changePin: "Change PIN…",
    unblockPin: "Unblock PIN with PUK…",
    resetKey: "Reset YubiKey…",
    currentPin: "Current PIN",
    puk: "PUK",
    newPinHint: "6 to 8 characters. The PIN is asked for with every signature.",
    pinLocked: "The PIN is locked",
    unblockShort: "Unblock…",
    holdsNothing: "This YubiKey holds no CA any more",
    protect: {
      title: "A PIN of your own",
      about:
        "This YubiKey still has the PIN every YubiKey ships with, so whoever gets hold of it can sign with its CA. Its CA stays as it is and works with the new PIN.",
      confirm: "Set PIN and PUK",
      done: "This YubiKey has a PIN and a PUK of your own now.",
    },
    change: {
      title: "Change PIN",
      about:
        "Only the PIN changes. What is on this YubiKey stays as it is and works with the new PIN.",
      confirm: "Change PIN",
      done: "The PIN is changed.",
    },
    unblock: {
      title: "Unblock PIN",
      about:
        "Sets a new PIN with the PUK, for a PIN that is forgotten or locked. Take care: a wrong PUK costs one of its attempts, and nothing unblocks a PUK.",
      confirm: "Set new PIN",
      done: "The new PIN is set.",
    },
    reset: {
      title: "Reset this YubiKey?",
      about:
        "For when both the PIN and the PUK are lost, or to start over. It empties the certificate store of the YubiKey (PIV): every key and certificate in it is destroyed for good, and the PIN and PUK go back to the factory ones. Passkeys and whatever else the YubiKey holds outside that store are not touched.",
      confirm: "Reset YubiKey",
      done: "The YubiKey is reset. Its PIN is 123456 and its PUK 12345678 again, as on every new YubiKey. It gets a PIN of its own when you put a CA on it.",
      // Said after what the key holds, if that is a CA of the open workspace.
      ofWorkspace: {
        root: "It is the root CA of this workspace: without it nothing here can be signed, replaced or revoked any more.",
        issuing:
          "It is the issuing CA of this workspace; the root CA can make a new one afterwards.",
      } satisfies Record<CaRole, string>,
      otherSlots: (slots: string[]) =>
        slots.length === 1
          ? `It also holds a certificate in slot ${slots[0]}, which goes too.`
          : `It also holds certificates in slots ${slots.join(", ")}, which go too.`,
    },
  },
  keyMismatch: "The key on this YubiKey does not match its certificate",
  wrongKey: "This YubiKey holds a different CA than the workspace folder",
  keyMadeInside:
    "The key of this CA was made inside its YubiKey and cannot be copied out. The YubiKey's own proof of that is kept in the workspace folder.",
  keyMadeInsideSaid: "The YubiKey says that the key of this CA was made inside it.",
  keyImported: "This key was put into the YubiKey from outside. Copies of it may exist.",
  rootShouldRest: "Not needed for everyday work. Safer unplugged.",
  otherKeys: "Other YubiKeys",
  holdsOtherCa: (subject: string) => `Holds “${subject}”, which is not part of this workspace`,
  // A key without a CA: the slot a CA would be in is empty, or something
  // is in it that is not a CA. The two are told apart, because the first
  // is free to use and the second would lose what it holds.
  holdsNoCa: "This YubiKey has an empty CA slot",
  holdsNotCa: "This YubiKey has something other than a CA in its CA slot",
  unusableKey: "Cannot be used",

  // Certificates
  certificates: "Certificates",
  search: "Search by name or group",
  newCertificate: "New certificate",
  noCertificates: "No certificates yet",
  noCertificatesBody: "Certificates you issue will show up here.",
  noMatches: "No certificate matches",
  columnName: "Name",
  columnKind: "For",
  columnStatus: "Status",
  columnExpires: "Expires",
  more: (count: number) => `+${count} more`,
  signedByRoot: "Signed by the root directly",
  fromReplacedCa: "Signed by a replaced issuing CA",
  fromRevokedCa: "Its issuing CA was revoked. Renew it.",
  replacesOther: "Replaces an earlier certificate",
  // What a certificate is for, said by its purpose: someone after an "SSL
  // certificate for a web server" has to find it without knowing that the
  // thing is called a TLS server certificate. Short, for the list.
  profile: {
    "tls-server": "Web server",
    "tls-client": "Client sign-in",
    "ipsec-gateway": "VPN gateway",
    "ipsec-client": "VPN client",
  } satisfies Record<Profile, string>,
  // The same with the name of the technology, where a kind is chosen.
  profileTitle: {
    "tls-server": "Web server (SSL/TLS)",
    "tls-client": "Client sign-in (TLS)",
    "ipsec-gateway": "VPN gateway (IPsec)",
    "ipsec-client": "VPN client (IPsec)",
  } satisfies Record<Profile, string>,
  kindAll: "All kinds",
  status: {
    valid: "Valid",
    "expires-soon": "Expires soon",
    expired: "Expired",
    revoked: "Revoked",
  } satisfies Record<Status, string>,
  filterAll: "All",
  // Filters name a group of certificates, hence the plural where a
  // language has one.
  filter: {
    valid: "Valid",
    "expires-soon": "Expiring soon",
    expired: "Expired",
    revoked: "Revoked",
  } satisfies Record<Status, string>,
  inDays: (days: number) => (days === 1 ? "in 1 day" : `in ${days} days`),
  daysAgo: (days: number) => (days === 1 ? "1 day ago" : `${days} days ago`),
  today: "today",
  refresh: "Check YubiKeys again",

  // What can be done with a certificate in the list
  actions: "Actions",
  renew: "Renew…",
  changeNames: {
    server: "Change host name or IP address…",
    client: "Change name or e-mail address…",
  },
  revoke: "Revoke…",
  renewTitle: "Renew certificate",
  renewAbout:
    "Issues a new certificate for the same key and the same names. The device keeps its private key.",
  changeNamesTitle: {
    server: "Change host name or IP address",
    client: "Change name or e-mail address",
  },
  newNamesServer: "New names or IP addresses",
  newNameClient: "New name or e-mail address",
  changeNamesHintServer:
    "Separate several with commas. The device keeps its private key and gets a new certificate for these names.",
  changeNamesHint: "The device keeps its private key and gets a new certificate for this name.",
  revokeOld: "Revoke the certificate this one replaces",
  revokeOldHint: "Otherwise the old one stays valid until it expires.",
  renewDoneNote:
    "The private key did not change. Only the new certificate has to be installed on the device.",
  // Where the old certificate's key is inside its .p12 file.
  renewOpensHint: "The private key is inside that file. The new file opens with the same password.",
  revokeTitle: "Revoke this certificate?",
  revokeBody:
    "A revoked certificate cannot be made valid again. Devices learn of it only from the revocation list, which you sign afterwards.",
  revokeConfirm: "Revoke",
  delete: "Delete…",
  deleteTitle: "Delete this certificate?",
  // Deleting takes a certificate off the list and its files out of the
  // workspace; it does nothing to a certificate that is installed.
  deleteBody: {
    valid: (date: string) =>
      `The certificate itself goes on working: devices accept it until ${date}. Deleting takes it off this list and its files out of the workspace, the private key included, and it can then no longer be revoked. To stop it from working, revoke it instead.`,
    revoked: (date: string) =>
      `It goes off this list and its files out of the workspace, the private key included. It stays on the revocation list until ${date}, when it would have expired, so devices go on refusing it.`,
    expired:
      "It has expired and no device accepts it any more. Deleting takes it off this list and its files out of the workspace.",
    ofRevokedCa:
      "Its issuing CA was revoked, and devices that have the root CA's revocation list refuse it. Deleting takes it off this list and its files out of the workspace.",
  },
  deleteConfirm: "Delete",

  // Revocation lists
  roleInText: { root: "root CA", issuing: "issuing CA" } satisfies Record<CaRole, string>,
  unlisted: (count: number, role: string) =>
    count === 1
      ? `1 revoked certificate is not on a signed revocation list of the ${role} yet.`
      : `${count} revoked certificates are not on a signed revocation list of the ${role} yet.`,
  unlistedHint: (count: number) =>
    count === 1
      ? "Devices keep accepting it until they are given the new list."
      : "Devices keep accepting them until they are given the new list.",
  listExpires: (role: string, date: string) =>
    `The revocation list of the ${role} is current only until ${date}.`,
  listExpired: (role: string, date: string) =>
    `The revocation list of the ${role} ran out on ${date}.`,
  listExpiresHint: "Devices that check it need a new one by then.",
  // A CA that has signed certificates but no list yet: new, or put in
  // place of a replaced issuing CA.
  listMissing: (role: string) => `The ${role} has not signed a revocation list yet.`,
  listMissingHint: "Devices that check one refuse its certificates without it.",
  signList: "Sign revocation list…",
  listTitle: "Sign revocation list",
  listAbout: (role: string) =>
    `The ${role} signs a list of every certificate of its own that was revoked. A device needs the new file in order to refuse them.`,
  listDoneTitle: "The revocation list is signed",
  listDone: (number: number, date: string) => `Number ${number} · current until ${date}`,
  listCount: (count: number) =>
    count === 0
      ? "Names no certificate"
      : count === 1
        ? "Names 1 revoked certificate"
        : `Names ${count} revoked certificates`,
  sign: "Sign",

  // New certificate
  newTitle: "New certificate",
  stepKind: "What is it for?",
  profileHint: {
    "tls-server": "A website, or the web interface of a switch, a NAS or a printer",
    "ipsec-gateway": "The gateway of a VPN, which its clients connect to",
    "ipsec-client": "A laptop or phone that connects to the VPN",
    "tls-client": "A program or person that signs in to a server with a certificate",
  } satisfies Record<Profile, string>,
  namesServer: "Names or IP addresses",
  namesServerPlaceholder: "nas.example.com, 192.168.1.20",
  namesServerHint: "Separate several with commas. The first one is the main name.",
  nameClient: "Name or e-mail address",
  nameClientPlaceholder: "alice@example.com",
  // How the device takes the certificate: what its upload form asks for.
  // The choices are told apart by what is on that form, never by a make
  // or a kind of device.
  files: {
    title: "How does the device take it?",
    option: {
      fullchain: "Certificate and private key",
      separate: "Certificate, intermediate and private key",
      p12: "One file with a password",
    },
    about: {
      fullchain: "Two files. The certificate file holds the intermediate CA too (fullchain).",
      separate: "Three files, one for each field of the form.",
      p12: "Everything together, as .p12 or .pfx. Also what a laptop or a phone imports.",
    },
    // Signed by the root CA there is no intermediate CA. The choice with
    // a file for one stays in sight, switched off: whoever has a form
    // with a field for it looks for it, and reads here what to do.
    aboutNoChain: {
      fullchain: "Two files. The root CA signs it directly, so there is no intermediate CA.",
      separate: "No intermediate CA here: the root CA signs directly. Leave that field empty.",
      p12: "",
    },
    // For a device that made its own key: the same, without the key.
    optionNoKey: {
      fullchain: "Certificate",
      separate: "Certificate and intermediate",
      p12: "",
    },
    aboutNoKey: {
      fullchain: "One file. It holds the intermediate CA too (fullchain).",
      separate: "Two files, one for each field of the form.",
      p12: "",
    },
    aboutNoKeyNoChain: {
      fullchain: "One file. The root CA signs it directly, so there is no intermediate CA.",
      separate: "No intermediate CA here: the root CA signs directly. Leave that field empty.",
      p12: "",
    },
    now: "as it is now",
  },
  // Where the key comes from: the app makes one, unless the device did.
  ownKey: "The device made its own key",
  ownKeyHint: "It gave you a request file (CSR). Its private key stays in the device.",
  requestChange: "Choose another…",
  requestPick: "Choose the device's request file",
  requestNote:
    "The private key never left the device. Only certificates were written; install them there.",
  p12Password: "Password for the file",
  p12PasswordRepeat: "Repeat the password",
  p12PasswordHint: "Whoever installs the certificate will be asked for it.",
  passwordsDiffer: "The two passwords differ",
  // Choices most people leave as they are.
  options: "Options",
  validity: "Valid for",
  validityLongest: "As long as possible",
  validityDays: (days: number) =>
    days < 365 ? `${days} days` : days === 365 ? "1 year" : `${Math.round(days / 365)} years`,
  validityHintServer:
    "As long as possible is 825 days: browsers and Apple devices refuse a server certificate that is valid for longer.",
  validityHintOther: (date: string) =>
    `As long as possible is until the CA itself expires, on ${date}.`,
  keyKind: "Key",
  keyKindChoice: { rsa: "RSA 2048", ecdsa: "ECC P-256" },
  keyKindHint:
    "RSA works with every device. ECC is smaller and faster, but some older devices cannot use it.",
  p12Compatible: "Make the file for an older system",
  p12CompatibleHint:
    "Uses older, weaker encryption. Only for a device that refuses the file otherwise.",
  noChain: "The device cannot handle a certificate chain",
  noChainHint: "The root CA signs directly. Its YubiKey has to be connected.",
  signedBy: (role: string) => `Signed by: ${role}`,
  connectKey: (serial: number) => `Connect the YubiKey with serial number ${serial} to continue`,
  noIssuingYet: "There is no issuing CA yet",
  back: "Back",
  next: "Continue",
  cancel: "Cancel",
  pinHint: "The PIN is sent to the YubiKey and nowhere else.",
  issue: "Issue certificate",
  checkingPin: "Checking the PIN…",
  touchTitle: "Touch your YubiKey",
  touchHint: "It is blinking and waits for your touch.",
  doneTitle: "The certificate is issued",
  doneValid: (date: string) => `Valid until ${date}`,
  doneFiles: "Files",
  trustAfter: "Whatever connects to it has to trust your root CA, which is not among these files.",
  showInFinder: "Show in Finder",
  done: "Done",
  // What a file holds when the root CA signed the certificate itself.
  // The root CA signed it itself: nothing comes with the certificate.
  fileFromRoot: {
    "certificate.crt":
      "The certificate. Goes where the certificate is asked for; there is no intermediate CA.",
  } as Record<string, string>,
  file: {
    "fullchain.crt":
      "The certificate with the intermediate CA below it. Goes where the certificate is asked for.",
    "certificate.crt": "The certificate. Goes where the certificate is asked for.",
    "intermediate-ca.crt":
      "The intermediate CA. Goes where the intermediate certificate is asked for.",
    "private-key.key": "The private key. Goes where the private key is asked for.",
    "certificate.p12":
      "Certificate, intermediate CA and private key in one. Opens with the password.",
    "issuing.crl.pem": "The revocation list of the issuing CA, in PEM form.",
    "issuing.crl": "The same in DER form, for devices that want that.",
    "root.crl.pem": "The revocation list of the root CA, in PEM form.",
    "root.crl": "The same in DER form, for devices that want that.",
  } as Record<string, string>,
  failure: {
    wrongPin: (left: number) =>
      left === 1 ? "Wrong PIN. 1 attempt left." : `Wrong PIN. ${left} attempts left.`,
    pinLocked: "The PIN is locked. Unblock it with the PUK first.",
    lastAttempt:
      "Only one PIN attempt is left. Enter the correct PIN once in another tool first, so a typo here cannot lock the key.",
    // The same three where two YubiKeys were asked for their PINs.
    wrongPinOn: (serial: number, left: number) =>
      left === 1
        ? `Wrong PIN for the YubiKey with serial number ${serial}. 1 attempt left.`
        : `Wrong PIN for the YubiKey with serial number ${serial}. ${left} attempts left.`,
    pinLockedOn: (serial: number) =>
      `The PIN of the YubiKey with serial number ${serial} is locked. Unblock it with the PUK first.`,
    lastAttemptOn: (serial: number) =>
      `Only one PIN attempt is left on the YubiKey with serial number ${serial}. Enter the correct PIN once in another tool first, so a typo here cannot lock the key.`,
    wrongPuk: (left: number) =>
      left === 1
        ? "Wrong PUK. 1 attempt left, and nothing unblocks a PUK."
        : `Wrong PUK. ${left} attempts left, and nothing unblocks a PUK.`,
    pukLocked:
      "The PUK is locked as well. Only resetting the YubiKey is left, which destroys what is on it.",
    notTouched: "The YubiKey was not touched in time. Try again.",
    keyMissing: "The YubiKey that has to sign is not connected.",
    wrongPassword: "The password does not open the file. Nothing was signed.",
    interrupted: (cause: string) =>
      `A new key was made on the YubiKey, but the CA was not finished: ${cause}. Try again; the unfinished key will be replaced.`,
  },
};

/** Dates are written the same for everyone: day, short month, year. */
const locale = "en-GB";

const dateFormat = new Intl.DateTimeFormat(locale, { dateStyle: "medium" });

export function formatDate(iso: string): string {
  return dateFormat.format(new Date(iso));
}

/** “in 12 days”, “3 days ago”, or `null` when the date is far enough away
 *  that the calendar date alone says it better. */
export function relativeDays(iso: string, horizonDays = 60): string | null {
  const days = Math.round((new Date(iso).getTime() - Date.now()) / 86_400_000);
  if (Math.abs(days) > horizonDays) return null;
  if (days === 0) return t.today;
  return days > 0 ? t.inDays(days) : t.daysAgo(-days);
}

/** The common name out of a subject such as `C=CZ, CN=Home Root CA`. */
export function commonName(subject: string): string {
  const match = subject.match(/(?:^|,\s*)CN=([^,]+)/);
  return match ? match[1].trim() : subject;
}
