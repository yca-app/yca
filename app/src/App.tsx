import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDown,
  Ellipsis,
  Folder,
  FolderInput,
  FolderOpen,
  ListFilter,
  Plus,
  Search,
  ShieldCheck,
  ShieldPlus,
  TriangleAlert,
  Usb,
} from "lucide-react";

import { CertificateTable, type Sort, type SortKey } from "@/components/CertificateTable";
import { ConfirmDialog, type Confirmation } from "@/components/ConfirmDialog";
import { GroupDialog } from "@/components/GroupDialog";
import { KeyName } from "@/components/KeyTag";
import { KeyDialog, type KeyTask } from "@/components/KeyDialog";
import { RepackageDialog } from "@/components/RepackageDialog";
import { SetupWizard } from "@/components/SetupWizard";
import { SigningDialog, type Progress, type Task } from "@/components/SigningDialog";
import { TrustDialog } from "@/components/TrustDialog";
import { useUpdates } from "@/components/Updates";
import { KeyItems, Sidebar } from "@/components/Sidebar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import {
  api,
  type AgentReply,
  type AgentRequest,
  type CaRole,
  type Certificate,
  type Device,
  type Devices,
  type Pki,
  type Profile,
  type RetiredCa,
  type Status,
} from "@/lib/api";
import { profileIcon, profiles } from "@/lib/profiles";
import { commonName, formatDate, t } from "@/lib/text";
import { cn } from "@/lib/utils";

const REMEMBERED_FOLDER = "yca.pkiFolder";
const filters: (Status | "all")[] = ["all", "valid", "expires-soon", "revoked", "expired"];

// What the list can be narrowed down to by group: every certificate, those
// in no group, or one group by its name. No group can have the empty name.
const ALL_GROUPS = null;
const NO_GROUP = "";

// What comes first when the list is put in order by status: what needs
// looking at.
const statusRank: Record<Status, number> = { "expires-soon": 0, valid: 1, revoked: 2, expired: 3 };
const orders: Record<SortKey, (a: Certificate, b: Certificate) => number> = {
  name: (a, b) =>
    a.names[0].localeCompare(b.names[0], undefined, { numeric: true, sensitivity: "base" }),
  kind: (a, b) => t.profile[a.profile].localeCompare(t.profile[b.profile]),
  status: (a, b) => statusRank[a.status] - statusRank[b.status],
  expires: (a, b) => new Date(a.notAfter).getTime() - new Date(b.notAfter).getTime(),
};

export default function App() {
  const [pki, setPki] = useState<Pki | null>(null);
  const [devices, setDevices] = useState<Devices | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Status | "all">("all");
  // Which kind of certificate the list is narrowed down to.
  const [kind, setKind] = useState<Profile | "all">("all");
  // Which group it is narrowed down to.
  const [group, setGroup] = useState<string | null>(ALL_GROUPS);
  // The column the list is in order by; without one, newest first.
  const [sort, setSort] = useState<Sort | null>(null);
  // Whether rows are being picked, to be moved into a group together.
  const [picking, setPicking] = useState(false);
  // Serial numbers of the rows that are picked.
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  // The certificates being sorted into a group, and whether that is up.
  const [moving, setMoving] = useState<Certificate[]>([]);
  const [movingOpen, setMovingOpen] = useState(false);
  // The certificate whose files are being written again in another form.
  const [repacking, setRepacking] = useState<Certificate | null>(null);
  const [repackOpen, setRepackOpen] = useState(false);
  // What the signing dialog is for, and whether it is open. The task
  // outlives the closing so the dialog does not change as it fades out.
  const [task, setTask] = useState<Task>({ kind: "new" });
  const [signing, setSigning] = useState(false);
  // Where that dialog stands: being filled in, waiting for the YubiKey,
  // or showing a result that is only there to be read.
  const [progress, setProgress] = useState<Progress>("filling");
  // Whether its result has only just come up. Someone who has typed a PIN
  // and touched a key is told that it worked before anything else is put
  // in front of them.
  const [justDone, setJustDone] = useState(false);
  const progressed = useCallback((next: Progress) => {
    setProgress(next);
    if (next !== "done") return;
    setJustDone(true);
    window.setTimeout(() => setJustDone(false), 2000);
  }, []);
  const startTask = useCallback((next: Task) => {
    setTask(next);
    setProgress("filling");
    setJustDone(false);
    setSigning(true);
  }, []);
  // Whether the wizard that creates a new certificate authority is up.
  const [creating, setCreating] = useState(false);
  // Whether the same wizard is up to give the open workspace a new issuing
  // CA: its first, or one in place of the issuing CA it has.
  const [adding, setAdding] = useState(false);
  // What the user is being asked to confirm, and whether the question is up.
  const [asked, setAsked] = useState<Confirmation | null>(null);
  const [confirming, setConfirming] = useState(false);
  // The YubiKey that is getting a PIN of its own, and whether that is up.
  const [keyAsked, setKeyAsked] = useState<{ device: Device; task: KeyTask } | null>(null);
  const [keyOpen, setKeyOpen] = useState(false);
  // Whether the steps for making devices trust this CA are up.
  const [trusting, setTrusting] = useState(false);
  const ask = useCallback((question: Confirmation) => {
    setAsked(question);
    setConfirming(true);
  }, []);

  const openFolder = useCallback(async (path: string) => {
    try {
      setPki(await api.openPki(path));
      setError(null);
      localStorage.setItem(REMEMBERED_FOLDER, path);
    } catch (reason) {
      setPki(null);
      setError(`${t.couldNotOpen}: ${String(reason)}`);
    }
  }, []);

  const pickFolder = useCallback(async () => {
    const path = await api.pickFolder();
    if (path) await openFolder(path);
  }, [openFolder]);

  // Takes a freshly started or extended PKI as the open one.
  const adopted = useCallback((result: Pki) => {
    setPki(result);
    setError(null);
    localStorage.setItem(REMEMBERED_FOLDER, result.path);
  }, []);

  const startFromKeys = useCallback(
    async (name: string) => {
      const path = await api.pickNewFolder(t.adoptWhere, name);
      if (!path) return;
      try {
        adopted(await api.adoptPki(path));
      } catch (reason) {
        setError(`${t.couldNotAdopt}: ${String(reason)}`);
      }
    },
    [adopted],
  );

  // The issuing CA that the sidebar offered, by the serial number of its
  // YubiKey: what is taken is the one that was shown.
  const adoptIssuing = useCallback(
    async (serial: number) => {
      if (!pki) return;
      try {
        adopted(await api.adoptIssuing(pki.path, serial));
      } catch (reason) {
        setError(String(reason));
      }
    },
    [pki, adopted],
  );

  // Which issuing CA belongs is judged against the open PKI's root, so
  // the keys are looked at again whenever another folder is opened.
  const pkiPath = pki?.path ?? null;
  const refreshDevices = useCallback(async () => {
    try {
      setDevices(await api.devices(pkiPath));
    } catch {
      // The keys cannot be looked at while one of them is signing. Keep
      // what was known; only a first look that fails shows "none".
      setDevices((known) => known ?? { usable: [], unusable: [] });
    }
  }, [pkiPath]);

  // Come back to the folder that was open last time. One that is not
  // there any more is forgotten without a word: whoever deleted it knows,
  // and an error about a folder nobody asked to open only alarms.
  useEffect(() => {
    const remembered = localStorage.getItem(REMEMBERED_FOLDER);
    if (!remembered) return;
    void api
      .workspaceStamp(remembered)
      .catch(() => undefined)
      .then((stamp) => {
        if (stamp === null) localStorage.removeItem(REMEMBERED_FOLDER);
        else void openFolder(remembered);
      });
  }, [openFolder]);

  // Another program may change the workspace: the command line, or an
  // agent working through it. The window asks every second whether anything
  // was written and looks again when it was, so that what they do shows up
  // here as if it had been done here.
  useEffect(() => {
    if (pkiPath === null) return;
    let known: string | null | undefined;
    let watching = true;
    const look = async () => {
      const stamp = await api.workspaceStamp(pkiPath).catch(() => undefined);
      if (!watching || stamp === undefined) return;
      if (stamp === null) {
        // The folder went while it was open: deleted, moved or its disk
        // unplugged. The window lets go of it and says so.
        watching = false;
        localStorage.removeItem(REMEMBERED_FOLDER);
        setPki(null);
        setError(t.workspaceGone(pkiPath));
        return;
      }
      if (known !== undefined && stamp !== known) void openFolder(pkiPath);
      known = stamp;
    };
    void look();
    const timer = window.setInterval(() => void look(), 1000);
    return () => {
      watching = false;
      window.clearInterval(timer);
    };
  }, [pkiPath, openFolder]);

  // YubiKeys come and go; look again every few seconds and on return to
  // the window.
  useEffect(() => {
    void refreshDevices();
    const timer = window.setInterval(() => void refreshDevices(), 3000);
    window.addEventListener("focus", refreshDevices);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshDevices);
    };
  }, [refreshDevices]);

  // Whether a certificate passes the filters, all of them or all but one.
  const passes = useCallback(
    (certificate: Certificate, except?: "status" | "kind" | "group") =>
      (except === "status" || filter === "all" || certificate.status === filter) &&
      (except === "kind" || kind === "all" || certificate.profile === kind) &&
      (except === "group" || group === ALL_GROUPS || (certificate.group ?? NO_GROUP) === group),
    [filter, kind, group],
  );
  // The filters narrow each other down, so each one's numbers say what
  // choosing it would show with the others left as they are.
  const counts = useMemo(() => {
    const others = (pki?.certificates ?? []).filter((c) => passes(c, "status"));
    const result: Record<Status | "all", number> = {
      all: others.length,
      valid: 0,
      "expires-soon": 0,
      revoked: 0,
      expired: 0,
    };
    for (const certificate of others) result[certificate.status] += 1;
    return result;
  }, [pki, passes]);
  const kindCounts = useMemo(() => {
    const others = (pki?.certificates ?? []).filter((c) => passes(c, "kind"));
    const result: Record<Profile | "all", number> = {
      all: others.length,
      "tls-server": 0,
      "tls-client": 0,
      "ipsec-gateway": 0,
      "ipsec-client": 0,
    };
    for (const certificate of others) result[certificate.profile] += 1;
    return result;
  }, [pki, passes]);
  // The groups of this workspace by name, and how many certificates each
  // would show; under the empty name, those in no group.
  const groups = useMemo(
    () =>
      [
        ...new Set((pki?.certificates ?? []).flatMap((c) => (c.group === null ? [] : [c.group]))),
      ].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true })),
    [pki],
  );
  const groupCounts = useMemo(() => {
    const others = (pki?.certificates ?? []).filter((c) => passes(c, "group"));
    const result = new Map<string | null, number>([[ALL_GROUPS, others.length]]);
    for (const certificate of others) {
      const name = certificate.group ?? NO_GROUP;
      result.set(name, (result.get(name) ?? 0) + 1);
    }
    return result;
  }, [pki, passes]);
  // A group that was emptied is nothing to stay narrowed down to.
  useEffect(() => {
    if (group !== ALL_GROUPS && group !== NO_GROUP && !groups.includes(group)) {
      setGroup(ALL_GROUPS);
    }
  }, [group, groups]);
  // The kinds this workspace has any certificate of.
  const kinds = useMemo(
    () =>
      profiles.filter((profile) =>
        (pki?.certificates ?? []).some((certificate) => certificate.profile === profile),
      ),
    [pki],
  );

  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    // A serial number is long and all hexadecimal digits, as copied from a
    // device or a log; a short word like "ad" is not taken for one.
    const serial = needle.replace(/[:\s]/g, "");
    const asSerial = /^[0-9a-f]{6,}$/.test(serial);
    const found = (pki?.certificates ?? []).filter(
      (certificate) =>
        passes(certificate) &&
        (needle === "" ||
          certificate.names.some((name) => name.toLowerCase().includes(needle)) ||
          (certificate.group?.toLowerCase().includes(needle) ?? false) ||
          (asSerial && certificate.serial.includes(serial))),
    );
    if (sort === null) return found;
    // Equal ones stay newest first.
    const order = orders[sort.by];
    return [...found].sort((a, b) => (sort.descending ? order(b, a) : order(a, b)));
  }, [pki, query, passes, sort]);
  // What is picked and in view: nothing is done to a row that a filter
  // has taken out of sight.
  const picked = useMemo(
    () => shown.filter((certificate) => selected.has(certificate.serial)),
    [shown, selected],
  );
  // Rows are picked only between pressing "Move" and moving them or
  // giving up: a click on a row does nothing the rest of the time.
  const stopPicking = () => {
    setPicking(false);
    setSelected(new Set());
  };
  // Escape gives up, unless a dialog is up that it is for.
  useEffect(() => {
    if (!picking) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !document.querySelector("[role=dialog], [role=menu]")) {
        setPicking(false);
        setSelected(new Set());
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [picking]);
  // Nor does it outlast the workspace the rows were in.
  const openPath = pki?.path;
  useEffect(() => {
    setPicking(false);
    setSelected(new Set());
  }, [openPath]);

  // What a program working on the person's behalf asks for: whatever takes
  // a PIN and a touch, or destroys something. It gets the dialog the person
  // would have opened themselves, filled in and saying who asks, and is
  // told how it ended.
  //
  // The person is never interrupted. A request that comes while they are
  // in the middle of something waits its turn; only a result that is just
  // standing there to be read gives way, once it has stood for a moment.
  // And a request whose program has gone away is dropped, so that nothing
  // comes up that nobody waits for.
  const waiting = useRef<AgentRequest[]>([]);
  const resting = signing && progress === "done" && !justDone;
  const elsewhere =
    (signing && !resting) ||
    creating ||
    adding ||
    confirming ||
    keyOpen ||
    movingOpen ||
    repackOpen ||
    trusting;
  // A newer version of the app: the line that says there is one, and the
  // dialog that installs it. That dialog is something the person is in
  // the middle of like any other, and waits its turn like any other.
  const updates = useUpdates({
    occupied: elsewhere,
    makeRoom: () => {
      if (resting) setSigning(false);
    },
  });
  const occupied = elsewhere || updates.open;
  // The functions below are kept in refs: the listener is set up once and
  // has to meet the window as it is now, also after it has waited for
  // something. `seen` is the window as of the last time it was drawn.
  const seen = useRef({ occupied, resting });
  seen.current = { occupied, resting };
  // Whether a request is being worked out this very moment.
  const working = useRef(false);

  // Puts one request before the person. Says whether a dialog came of it.
  const putBefore = useRef<(request: AgentRequest) => Promise<boolean>>(async () => false);
  putBefore.current = async (request) => {
    const reply = (answer: AgentReply) => void api.answerAgent(request.id, answer);
    const failed = (message: string) => {
      reply({ state: "failed", message });
      return false;
    };
    const { ask: wanted, from, id } = request;
    // The workspace it is about. The window turns to it only once there
    // is something to show: a request that is turned down changes nothing
    // the person sees.
    let workspace = pki;
    if (wanted.kind !== "setup" && request.workspace !== null && request.workspace !== pki?.path) {
      try {
        workspace = await api.openPki(request.workspace);
      } catch (reason) {
        return failed(String(reason));
      }
    }
    // A certificate by its serial number, or an unambiguous beginning of it.
    const find = (serial: string) => {
      const start = serial.toLowerCase().replace(/[:\s]/g, "");
      const found = (workspace?.certificates ?? []).filter((c) => c.serial.startsWith(start));
      return start !== "" && found.length === 1 ? found[0] : null;
    };
    // Everything that can be wrong with it is found out before anything
    // on the screen moves.
    let show: () => void;
    switch (wanted.kind) {
      case "setup":
        if (wanted.issuing && !pki) return failed(t.agent.noWorkspace);
        // The wizard for a new authority starts where no workspace is open.
        show = () => {
          if (wanted.issuing) setAdding(true);
          else {
            setPki(null);
            setCreating(true);
          }
        };
        break;
      case "issue":
        show = () =>
          startTask({
            kind: "new",
            group: wanted.group,
            asked: { ...wanted, id, from, answer: reply },
          });
        break;
      case "sign-request": {
        let names = wanted.names;
        try {
          const read = await api.readRequest(wanted.csrPath);
          if (names.length === 0) names = read.names;
        } catch (reason) {
          return failed(String(reason));
        }
        show = () =>
          startTask({
            kind: "new",
            group: wanted.group,
            asked: { ...wanted, names, id, from, answer: reply },
          });
        break;
      }
      case "reissue": {
        const certificate = find(wanted.serial);
        if (!certificate) return failed(t.agent.noCertificate(wanted.serial));
        if (certificate.revokedAt !== null) return failed(t.agent.revoked);
        show = () =>
          startTask({
            kind: wanted.names.length > 0 ? "change" : "renew",
            certificate,
            asked: { ...wanted, id, from, answer: reply },
          });
        break;
      }
      case "sign-list":
        if (wanted.role === "issuing" && workspace?.issuing === null) {
          return failed(t.agent.noIssuing);
        }
        show = () =>
          startTask({ kind: "list", role: wanted.role, asked: { id, from, answer: reply } });
        break;
      case "delete": {
        const certificate = find(wanted.serial);
        if (!certificate) return failed(t.agent.noCertificate(wanted.serial));
        show = () =>
          ask({
            title: t.deleteTitle,
            subject: certificate.names.join(", "),
            body: whatDeletingMeans(certificate),
            confirm: t.deleteConfirm,
            run: () => api.deleteCertificate(workspace!.path, certificate.serial),
            from,
            requestId: id,
            onSettled: (done) =>
              reply(
                done
                  ? { state: "done", result: { deleted: certificate.serial } }
                  : { state: "declined" },
              ),
          });
        break;
      }
    }
    if (wanted.kind !== "setup" && !workspace) return failed(t.agent.noWorkspace);
    // Working it out took a moment, and the person may have started on
    // something of their own meanwhile. Then it goes back to wait.
    if (seen.current.occupied) {
      waiting.current.unshift(request);
      reply({ state: "queued" });
      return true;
    }
    // A result that was only standing there to be read gives way.
    if (seen.current.resting) setSigning(false);
    if (workspace && workspace.path !== pki?.path) adopted(workspace);
    show();
    reply({ state: "shown" });
    if (wanted.kind === "setup") reply({ state: "done", result: { opened: true } });
    return true;
  };

  // Takes the next request, as long as the person is not in the middle of
  // something; one that is turned down unseen makes way for the one after.
  const showNext = useRef<() => Promise<void>>(async () => {});
  showNext.current = async () => {
    if (working.current) return;
    working.current = true;
    try {
      while (!seen.current.occupied) {
        const request = waiting.current.shift();
        if (!request) break;
        if (await putBefore.current(request)) break;
      }
    } finally {
      working.current = false;
    }
  };
  // Whenever the person is done with something, the next one's turn comes.
  useEffect(() => {
    if (!occupied) void showNext.current();
  }, [occupied]);

  // The program behind a request has gone. A request that still waited is
  // forgotten; a dialog it had opened is closed, unless the YubiKey is
  // signing this very moment or the result is already there.
  const forget = useRef<(id: string) => void>(() => {});
  forget.current = (id) => {
    const at = waiting.current.findIndex((request) => request.id === id);
    if (at >= 0) {
      waiting.current.splice(at, 1);
      return;
    }
    if (signing && task.asked?.id === id && progress === "filling") setSigning(false);
    if (confirming && asked?.requestId === id) setConfirming(false);
  };

  useEffect(() => {
    let stop: (() => void) | undefined;
    let gone = false;
    void api
      .onAgentRequest(
        (request) => {
          waiting.current.push(request);
          // It is told that it waits, unless its turn is right now.
          if (seen.current.occupied || working.current) {
            void api.answerAgent(request.id, { state: "queued" });
          }
          void showNext.current();
        },
        (id) => forget.current(id),
      )
      .then((stopListening) => {
        if (gone) stopListening();
        else stop = stopListening;
      });
    return () => {
      gone = true;
      stop?.();
    };
  }, []);

  if (!pki && creating) {
    return (
      <SetupWizard
        devices={devices}
        onCancel={() => setCreating(false)}
        onCreated={(created) => {
          setCreating(false);
          adopted(created);
        }}
      />
    );
  }
  if (!pki) {
    return (
      <>
        <Welcome
          devices={devices}
          error={error}
          onOpen={pickFolder}
          onStartFromKeys={startFromKeys}
          onCreate={() => setCreating(true)}
          onKeyTask={(device, task) => {
            setKeyAsked({ device, task });
            setKeyOpen(true);
          }}
          notice={updates.notice}
        />
        {updates.dialog}
        {/* A YubiKey's PIN and its reset need no workspace: a key is
            often reset precisely in order to start one. */}
        <KeyDialog
          open={keyOpen}
          onOpenChange={setKeyOpen}
          device={keyAsked?.device ?? null}
          task={keyAsked?.task ?? "change"}
          workspaceRole={null}
          onDone={() => void refreshDevices()}
        />
      </>
    );
  }

  if (adding) {
    return (
      <SetupWizard
        devices={devices}
        workspace={pki}
        onCancel={() => setAdding(false)}
        onCreated={(extended) => {
          setAdding(false);
          adopted(extended);
        }}
      />
    );
  }

  const path = pki.path;
  const askRevoke = (certificate: Certificate) =>
    ask({
      title: t.revokeTitle,
      subject: certificate.names.join(", "),
      body: t.revokeBody,
      confirm: t.revokeConfirm,
      run: () => api.revoke(path, certificate.serial),
    });
  const askDelete = (certificate: Certificate) =>
    ask({
      title: t.deleteTitle,
      subject: certificate.names.join(", "),
      body: whatDeletingMeans(certificate),
      confirm: t.deleteConfirm,
      run: () => api.deleteCertificate(path, certificate.serial),
    });
  const move = (certificates: Certificate[]) => {
    setMoving(certificates);
    setMovingOpen(true);
  };
  // A click on a heading puts the list in that column's order, a second
  // one turns it round, a third leaves it as it was issued.
  const sortBy = (by: SortKey) =>
    setSort((now) =>
      now?.by !== by ? { by, descending: false } : now.descending ? null : { by, descending: true },
    );
  const askRevokeCa = (ca: RetiredCa) =>
    ask({
      title: t.revokeCaTitle,
      subject: commonName(ca.subject),
      body: t.revokeCaBody,
      confirm: t.revokeConfirm,
      run: () => api.revokeReplacedCa(path, ca.serial),
    });

  return (
    <div className="flex h-screen">
      <Sidebar
        pki={pki}
        devices={devices}
        error={error}
        onOpenAnother={pickFolder}
        onRefresh={refreshDevices}
        onAdoptIssuing={adoptIssuing}
        onAddIssuing={() => setAdding(true)}
        onReplaceIssuing={() => setAdding(true)}
        onRevokeReplaced={askRevokeCa}
        onKeyTask={(device, task) => {
          setKeyAsked({ device, task });
          setKeyOpen(true);
        }}
        onTrust={() => setTrusting(true)}
        onClose={() => {
          localStorage.removeItem(REMEMBERED_FOLDER);
          setPki(null);
          setError(null);
        }}
      />

      <main className="flex min-w-0 flex-1 flex-col">
        <header
          data-tauri-drag-region
          className="flex h-14 shrink-0 items-center gap-3 border-b px-6"
        >
          <h1 className="text-xl font-semibold" data-tauri-drag-region>
            {t.certificates}
          </h1>
          <div className="relative ml-auto w-64">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t.search}
              className="h-8 pl-8"
              type="search"
            />
          </div>
          {/* The default size: as tall as the search field next to it. A
              certificate issued while the list shows one group goes into
              that group, unless its owner says otherwise. */}
          <Button
            onClick={() =>
              startTask({
                kind: "new",
                group: group === ALL_GROUPS || group === NO_GROUP ? null : group,
              })
            }
          >
            <Plus />
            {t.newCertificate}
          </Button>
        </header>

        {/* Below the toolbar the window reads like a page: the filters,
            then the list in a card of its own, with room around it. */}
        <div className="relative flex min-h-0 flex-1 flex-col gap-3 px-6 py-4">
          {updates.notice}
          {listNotices(pki).map((notice) => (
            <div
              key={notice.role}
              className="flex shrink-0 items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2"
            >
              <TriangleAlert className="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <p className="min-w-0 flex-1">
                {notice.text} <span className="text-muted-foreground">{notice.hint}</span>
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => startTask({ kind: "list", role: notice.role })}
              >
                {t.signList}
              </Button>
            </div>
          ))}
          <div className="flex shrink-0 items-center gap-1">
            {filters
              // The chosen one stays, even when it has nothing to show.
              .filter((name) => name === "all" || counts[name] > 0 || filter === name)
              .map((name) => (
                <button
                  key={name}
                  onClick={() => setFilter(name)}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-sm font-medium transition-colors",
                    filter === name
                      ? "bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {name === "all" ? t.filterAll : t.filter[name]}
                  <span className="ml-1.5 tabular-nums opacity-60">{counts[name]}</span>
                </button>
              ))}
            <div className="ml-auto flex items-center gap-1">
              {/* Turns the rows into something to tick, and back. */}
              {pki.certificates.length > 0 && (
                <button
                  aria-pressed={picking}
                  title={t.group.pickTitle}
                  onClick={() => (picking ? stopPicking() : setPicking(true))}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
                    picking
                      ? "bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <FolderInput className="size-3.5" strokeWidth={1.75} />
                  {t.group.pick}
                </button>
              )}
              {/* There once anything has been sorted into a group. */}
              {(groups.length > 0 || group !== ALL_GROUPS) && (
                <GroupFilter
                  group={group}
                  groups={groups}
                  counts={groupCounts}
                  onChoose={setGroup}
                />
              )}
              {/* Worth offering once there is more than one kind to tell apart. */}
              {(kinds.length > 1 || kind !== "all") && (
                <KindFilter kind={kind} kinds={kinds} counts={kindCounts} onChoose={setKind} />
              )}
            </div>
          </div>

          {shown.length > 0 ? (
            <CertificateTable
              certificates={shown}
              // Under the headings of their groups, unless the list shows
              // one group alone or there are none.
              sections={group === ALL_GROUPS && groups.length > 0}
              picking={picking}
              sort={sort}
              onSort={sortBy}
              selected={selected}
              onSelect={setSelected}
              onMove={(certificate) => move([certificate])}
              onRepackage={(certificate) => {
                setRepacking(certificate);
                setRepackOpen(true);
              }}
              markRootSigned={pki.issuing !== null}
              onRenew={(certificate) => startTask({ kind: "renew", certificate })}
              onChangeNames={(certificate) => startTask({ kind: "change", certificate })}
              onRevoke={askRevoke}
              onDelete={askDelete}
              onShow={(certificate) =>
                certificate.location && void api.reveal(certificate.location)
              }
            />
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-1 text-center">
              <p className="font-medium">
                {pki.certificates.length === 0 ? t.noCertificates : t.noMatches}
              </p>
              {pki.certificates.length === 0 && (
                <p className="text-sm text-muted-foreground">{t.noCertificatesBody}</p>
              )}
            </div>
          )}

          {/* While rows are being picked: what to do, how many are ticked,
              and the way on or out. It floats over the foot of the list, so
              that ticking a row moves nothing. */}
          {picking && (
            <div className="pointer-events-none absolute inset-x-0 bottom-7 flex justify-center">
              <div className="pointer-events-auto flex items-center gap-1 rounded-lg border bg-popover py-1 pr-1 pl-3 text-sm shadow-lg">
                <span className="mr-2 tabular-nums text-muted-foreground">
                  {picked.length === 0 ? t.group.pickHint : t.group.selected(picked.length)}
                </span>
                <Button size="sm" disabled={picked.length === 0} onClick={() => move(picked)}>
                  <Folder />
                  {t.group.move}
                </Button>
                <Button variant="ghost" size="sm" onClick={stopPicking}>
                  {t.cancel}
                </Button>
              </div>
            </div>
          )}
        </div>
      </main>

      <SigningDialog
        open={signing}
        onOpenChange={setSigning}
        task={task}
        pki={pki}
        devices={devices}
        onSigned={() => void openFolder(pki.path)}
        onProgress={progressed}
        onTrust={() => {
          setSigning(false);
          setTrusting(true);
        }}
      />
      <RepackageDialog
        open={repackOpen}
        onOpenChange={setRepackOpen}
        certificate={repacking}
        path={pki.path}
        onDone={setPki}
        onShow={(folder) => void api.reveal(folder)}
      />
      <TrustDialog open={trusting} onOpenChange={setTrusting} pki={pki} />
      <GroupDialog
        open={movingOpen}
        onOpenChange={setMovingOpen}
        certificates={moving}
        groups={groups}
        path={pki.path}
        onDone={(sorted) => {
          setPki(sorted);
          stopPicking();
        }}
      />
      <KeyDialog
        open={keyOpen}
        onOpenChange={setKeyOpen}
        device={keyAsked?.device ?? null}
        task={keyAsked?.task ?? "change"}
        workspaceRole={
          keyAsked?.device.serial === pki.root.yubikey
            ? "root"
            : keyAsked?.device.serial === pki.issuing?.yubikey
              ? "issuing"
              : null
        }
        onDone={() => void refreshDevices()}
      />
      <ConfirmDialog open={confirming} onOpenChange={setConfirming} asked={asked} onDone={setPki} />
      {updates.dialog}
    </div>
  );
}

/**
 * Narrows the list down to the certificates for one kind of use. It sits
 * at the far end of the row of status filters, and looks chosen when it
 * is narrowing anything.
 */
function KindFilter({
  kind,
  kinds,
  counts,
  onChoose,
}: {
  kind: Profile | "all";
  /** The kinds there is any certificate of. */
  kinds: Profile[];
  counts: Record<Profile | "all", number>;
  onChoose: (kind: Profile | "all") => void;
}) {
  const Icon = kind === "all" ? ListFilter : profileIcon[kind];
  const label = kind === "all" ? t.kindAll : t.profile[kind];
  // A kind that was chosen stays on offer, whatever the workspace holds.
  const offered = kind === "all" || kinds.includes(kind) ? kinds : [...kinds, kind];
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          // Named after the column it narrows down.
          aria-label={`${t.columnKind}: ${label}`}
          className={cn(
            "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
            kind === "all"
              ? "text-muted-foreground hover:text-foreground"
              : "bg-secondary text-secondary-foreground",
          )}
        >
          <Icon className="size-3.5" strokeWidth={1.75} />
          {label}
          <ChevronDown className="size-3 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuRadioGroup
          value={kind}
          onValueChange={(value) => onChoose(value as Profile | "all")}
        >
          <DropdownMenuRadioItem value="all">
            <ListFilter strokeWidth={1.75} />
            {t.kindAll}
            <span className="ml-auto tabular-nums text-muted-foreground">{counts.all}</span>
          </DropdownMenuRadioItem>
          {offered.map((profile) => {
            const KindIcon = profileIcon[profile];
            return (
              <DropdownMenuRadioItem key={profile} value={profile}>
                <KindIcon strokeWidth={1.75} />
                {t.profile[profile]}
                <span className="ml-auto tabular-nums text-muted-foreground">
                  {counts[profile]}
                </span>
              </DropdownMenuRadioItem>
            );
          })}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/**
 * Narrows the list down to one group, or to what is in none. Beside the
 * filter by kind, and like it looks chosen when it is narrowing anything.
 */
function GroupFilter({
  group,
  groups,
  counts,
  onChoose,
}: {
  /** The chosen group, {@link NO_GROUP} or {@link ALL_GROUPS}. */
  group: string | null;
  groups: string[];
  /** How many certificates each choice would show. */
  counts: Map<string | null, number>;
  onChoose: (group: string | null) => void;
}) {
  const label = group === ALL_GROUPS ? t.group.all : group === NO_GROUP ? t.group.none : group;
  // The menu's values are strings; no group can be called this.
  const all = "\u0000all";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          aria-label={`${t.group.label}: ${label}`}
          className={cn(
            "flex max-w-56 items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
            group === ALL_GROUPS
              ? "text-muted-foreground hover:text-foreground"
              : "bg-secondary text-secondary-foreground",
          )}
        >
          <Folder className="size-3.5 shrink-0" strokeWidth={1.75} />
          <span className="truncate">{label}</span>
          <ChevronDown className="size-3 shrink-0 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="max-h-80 w-60">
        <DropdownMenuRadioGroup
          value={group ?? all}
          onValueChange={(value) => onChoose(value === all ? ALL_GROUPS : value)}
        >
          <DropdownMenuRadioItem value={all}>
            {t.group.all}
            <span className="ml-auto tabular-nums text-muted-foreground">
              {counts.get(ALL_GROUPS) ?? 0}
            </span>
          </DropdownMenuRadioItem>
          {groups.map((name) => (
            <DropdownMenuRadioItem key={name} value={name}>
              <span className="truncate">{name}</span>
              <span className="ml-auto tabular-nums text-muted-foreground">
                {counts.get(name) ?? 0}
              </span>
            </DropdownMenuRadioItem>
          ))}
          {/* Not on offer while everything shown is in a group. */}
          {((counts.get(NO_GROUP) ?? 0) > 0 || group === NO_GROUP) && (
            <DropdownMenuRadioItem value={NO_GROUP}>
              {t.group.none}
              <span className="ml-auto tabular-nums text-muted-foreground">
                {counts.get(NO_GROUP) ?? 0}
              </span>
            </DropdownMenuRadioItem>
          )}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/**
 * Deleting takes a certificate off the list and does nothing to the
 * certificate itself, so what it means depends on whether devices still
 * accept it.
 */
function whatDeletingMeans(certificate: Certificate): string {
  const date = formatDate(certificate.notAfter);
  if (new Date(certificate.notAfter).getTime() <= Date.now()) return t.deleteBody.expired;
  // Revoked along with its issuing CA, it is on no list of its own.
  if (certificate.issuer === "revoked") return t.deleteBody.ofRevokedCa;
  return certificate.status === "revoked" ? t.deleteBody.revoked(date) : t.deleteBody.valid(date);
}

/**
 * What has to be said about the revocation lists: a CA whose list does not
 * name everything revoked, one whose list is about to run out, or an
 * issuing CA that took over from one with a list and has none of its own
 * yet. A device refuses a revoked certificate only once it has a list that
 * names it.
 *
 * A CA that has revoked nothing and never had a list is told nothing: there
 * is nothing to hand to devices, and a new authority should not start out
 * with a warning.
 */
function listNotices(pki: Pki): { role: CaRole; text: string; hint: string }[] {
  const soon = 30 * 24 * 60 * 60 * 1000;
  const notices = [];
  for (const role of ["issuing", "root"] as const) {
    const ca = role === "root" ? pki.root : pki.issuing;
    if (!ca) continue;
    const { unlisted, nextUpdate, number, replacedHadList } = ca.revocation;
    const name = t.roleInText[role];
    // Devices that were given the list of the CA this one replaced check
    // lists, and have none for what this CA signed and is still in use.
    const owesList =
      number === null &&
      replacedHadList &&
      pki.certificates.some(
        (c) => c.issuedBy === role && c.issuer === "current" && c.status !== "expired",
      );
    if (unlisted > 0) {
      notices.push({ role, text: t.unlisted(unlisted, name), hint: t.unlistedHint(unlisted) });
    } else if (owesList) {
      notices.push({ role, text: t.listMissing(name), hint: t.listMissingHint });
    } else if (nextUpdate && new Date(nextUpdate).getTime() - Date.now() < soon) {
      const date = formatDate(nextUpdate);
      const over = new Date(nextUpdate).getTime() < Date.now();
      notices.push({
        role,
        text: over ? t.listExpired(name, date) : t.listExpires(name, date),
        hint: t.listExpiresHint,
      });
    }
  }
  return notices;
}

/** What the window shows before any workspace is open. */
function Welcome({
  devices,
  error,
  onOpen,
  onStartFromKeys,
  onCreate,
  onKeyTask,
  notice,
}: {
  devices: Devices | null;
  error: string | null;
  /** Something the app has to say about itself, such as that a newer
   *  version is out. Said last, under what the screen is for. */
  notice?: React.ReactNode;
  onOpen: () => void;
  /** Changes a connected YubiKey's PIN, unblocks it or resets the key. */
  onKeyTask: (device: Device, task: KeyTask) => void;
  /** Starts the wizard that creates a new certificate authority. */
  onCreate: () => void;
  /** Starts a workspace from the connected keys; gets a name to suggest for its folder. */
  onStartFromKeys: (name: string) => void;
}) {
  const keys = devices?.usable ?? [];
  const roots = keys.filter((key) => key.ca?.role === "root");
  // Only one root can start a PKI, and only its own issuing CA comes along.
  const root = roots.length === 1 ? roots[0] : undefined;
  const issuing = root && keys.find((key) => key.ca?.role === "issuing" && key.ca.signedByRoot);
  // What the PKI starts from comes first, the root above its issuing CA,
  // so the list does not depend on the order the keys were plugged in.
  const rank = (key: Device) => (key.ca?.role === "root" ? 0 : key === issuing ? 1 : 2);
  const listed = [...keys].sort((a, b) => rank(a) - rank(b) || a.serial - b.serial);
  // What the screen leads with follows the keys. With no CA on any of
  // them, as when they are new, there is nothing to start from and one
  // way on: to make a CA. With a CA on them, the way on is to start from
  // it, and making a new one, which would destroy it, steps back.
  const nothingToStartFrom = keys.length > 0 && keys.every((key) => key.ca === null);

  return (
    <div data-tauri-drag-region className="flex h-screen items-center justify-center p-8">
      <div className="flex w-full max-w-md flex-col items-center text-center">
        <div className="mb-5 flex size-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
          <ShieldCheck className="size-7" strokeWidth={1.75} />
        </div>
        <h1 className="text-xl font-semibold tracking-tight">{t.welcomeTitle}</h1>
        <p className="mt-2 text-muted-foreground">{t.welcomeBody}</p>

        <div className="mt-6 w-full rounded-xl border text-left">
          <p className="border-b px-4 py-2 text-xs font-medium text-muted-foreground">
            {t.connectedKeys}
          </p>
          {keys.length === 0 ? (
            <p className="px-4 py-4 text-sm text-muted-foreground">
              {devices === null ? t.lookingForKeys : t.noKeysConnected}
            </p>
          ) : (
            <ul className="divide-y">
              {listed.map((key) => {
                // With a root to start from, every other key that is not
                // its issuing CA stays out of the new PKI.
                const leftOut = root !== undefined && key !== root && key !== issuing;
                return (
                  <li key={key.serial} className="flex items-start gap-3 px-4 py-2.5">
                    <Usb className="mt-0.5 size-4 shrink-0 text-connected" />
                    <span className="min-w-0 flex-1">
                      <span className={cn("block font-medium", leftOut && "text-muted-foreground")}>
                        {key.ca
                          ? t.holdsCa(t.role[key.ca.role], commonName(key.ca.subject))
                          : key.tooOld
                            ? t.tooOld
                            : key.keyWithoutCertificate
                              ? t.holdsLoneKey
                              : key.slotInUse
                                ? t.holdsNotCa
                                : t.holdsNoCa}
                      </span>
                      {/* Which key it is: two that look alike are told apart
                          by serial number, and what one of them can do by
                          its firmware. */}
                      <span className="mt-0.5 flex items-baseline gap-2 text-xs text-muted-foreground">
                        <KeyName serial={key.serial} />
                        <span title={t.firmwareAbout(key.firmware)}>
                          {t.firmware(key.firmware)}
                        </span>
                      </span>
                      {leftOut && key.ca?.role === "issuing" && (
                        <span className="mt-1 block text-xs text-amber-700 dark:text-amber-400">
                          {t.leftOut}
                        </span>
                      )}
                      {key.tooOld && (
                        <span className="mt-1 block text-xs text-amber-700 dark:text-amber-400">
                          {t.tooOldAbout}
                        </span>
                      )}
                      {/* The menu of the key puts it right. */}
                      {!key.factoryPin && key.factoryCredentials && (
                        <span className="mt-1 block text-xs text-amber-700 dark:text-amber-400">
                          {t.factoryOther}
                        </span>
                      )}
                    </span>
                    <DropdownMenu modal={false}>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="-mr-2 size-6 shrink-0 text-muted-foreground"
                          aria-label={t.actions}
                        >
                          <Ellipsis className="size-3.5" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-56">
                        <KeyItems device={key} onKeyTask={onKeyTask} />
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="border-t px-4 py-3">
            {keys.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t.connectToGoOn}</p>
            ) : nothingToStartFrom ? (
              <>
                <Button className="w-full" onClick={onCreate}>
                  <ShieldPlus />
                  {t.create}
                </Button>
                <p className="mt-2 text-xs text-muted-foreground">{t.createHint(keys.length)}</p>
              </>
            ) : (
              <>
                <Button
                  className="w-full"
                  disabled={!root}
                  onClick={() =>
                    root?.ca && onStartFromKeys(t.workspaceFolderName(commonName(root.ca.subject)))
                  }
                >
                  {root && !issuing ? t.adoptRootOnly : t.adopt}
                </Button>
                <p className="mt-2 text-xs text-muted-foreground">
                  {roots.length > 1
                    ? t.adoptOneRoot
                    : !root
                      ? t.adoptNeedsRoot
                      : issuing
                        ? t.adoptHint
                        : t.adoptHintRootOnly}
                </p>
                {root && (
                  <p className="mt-1.5 text-xs text-muted-foreground">{t.workspaceBackup}</p>
                )}
              </>
            )}
          </div>
        </div>

        <div className="mt-3 flex flex-col items-center gap-1">
          {/* Where it is not what the screen leads with. */}
          {!nothingToStartFrom && (
            <Button variant="ghost" onClick={onCreate}>
              <ShieldPlus />
              {t.create}
            </Button>
          )}
          <Button variant="ghost" onClick={onOpen}>
            <FolderOpen />
            {t.openFolder}
          </Button>
        </div>
        {error && (
          <p className="selectable mt-4 flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-left text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            {error}
          </p>
        )}
        {notice && <div className="mt-6 w-full">{notice}</div>}
      </div>
    </div>
  );
}
