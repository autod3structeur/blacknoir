import "./style.css";
import {
  ab,
  acceptResponder,
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64,
  deserializeState,
  fromUtf8,
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  randomBytes,
  ratchetDecrypt,
  ratchetEncrypt,
  safetyNumber,
  serializeState,
  sign,
  startInitiator,
  unb64,
  utf8,
  type Identity,
  type PreKeyBundle,
  type RatchetHeader,
  type X3DHInit,
} from "../crypto/index.ts";
import {
  createVault,
  isVaultBlob,
  openString,
  sealString,
  unlockVault,
  type VaultMeta,
} from "../crypto/vault.ts";

const AUTH_PREFIX = "blacknoir-Auth:";
const OPK_COUNT = 20;
const MAX_FILE = 8 * 1024 * 1024;
const VAULT_KEY = "blacknoir.vault";

interface StoredIdentity {
  username: string;
  edPriv: string;
  edPub: string;
  xPriv: string;
  xPub: string;
}

interface StoredPreKeys {
  spkPriv: string;
  spkPub: string;
  opkPrivs: Record<string, string>;
}

interface Attachment {
  id: string;
  key: string;
  iv: string;
  name: string;
  mime: string;
  size: number;
}

interface InnerMessage {
  kind: "text" | "file";
  text?: string;
  file?: Attachment;
}

type MsgStatus = "sending" | "queued" | "sent" | "delivered" | "failed";

interface ChatMessage {
  id?: string;
  from: string;
  text: string;
  ts: number;
  file?: Attachment;
  status?: MsgStatus;
}

interface OutboxItem {
  id: string;
  peer: string;
  payload: string;
  ts: number;
}

interface WirePayload {
  type: "prekey" | "msg";
  init?: X3DHInit;
  header: { dh: string; pn: number; n: number };
  ciphertext: string;
}

interface Envelope {
  id: string;
  from: string;
  to: string;
  payload: string;
  ts: number;
}

type VerifyStatus = "verified" | "unverified" | "changed";

const LS = {
  identity: "blacknoir.identity",
  prekeys: "blacknoir.prekeys",
  outbox: "blacknoir.outbox",
  session: (peer: string) => `blacknoir.session.${peer}`,
  history: (peer: string) => `blacknoir.history.${peer}`,
  peerKey: (peer: string) => `blacknoir.peerkey.${peer}`,
  verified: (peer: string) => `blacknoir.verified.${peer}`,
};

let identity: Identity | null = null;
let me = "";
let token = "";
let vaultKey: Uint8Array | null = null;
let socket: WebSocket | null = null;
let activePeer: string | null = null;
let users: string[] = [];
let onlineUsers = new Set<string>();
let searchTerm = "";
let connected = false;
let decryptQueue: Promise<void> = Promise.resolve();
let pendingFile: File | null = null;
let flushing = false;
let typing: { peer: string; until: number } | null = null;
let lastTypingSent = 0;

const histories = new Map<string, ChatMessage[]>();
const attachCache = new Map<string, string>();
const attachPending = new Set<string>();
const app = document.querySelector<HTMLDivElement>("#app")!;

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase();
}

function dpClass(name: string): string {
  const code = name.length > 0 ? name.charCodeAt(0) : 0;
  return `c${(code + name.length) % 5}`;
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function fileSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function statusLabel(status: MsgStatus): string {
  switch (status) {
    case "sending":
      return "Sending...";
    case "queued":
      return "Queued";
    case "sent":
      return "Sent";
    case "delivered":
      return "Delivered";
    case "failed":
      return "Failed";
  }
}

const ONLINE_ICON = `<svg class="status-icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <circle cx="8" cy="8" r="7" fill="#7ab648" stroke="#4f8a2a" />
  <circle cx="8" cy="6" r="2.2" fill="#fff" />
  <path d="M3.6 12.6a4.7 4.7 0 0 1 8.8 0z" fill="#fff" />
</svg>`;

const OFFLINE_ICON = `<svg class="status-icon" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <circle cx="8" cy="8" r="7" fill="#c3cbd4" stroke="#8b97a4" />
  <circle cx="8" cy="6" r="2.2" fill="#fff" />
  <path d="M3.6 12.6a4.7 4.7 0 0 1 8.8 0z" fill="#fff" />
</svg>`;

const PAPERCLIP = `<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
  <path d="M10.8 4.2 5.6 9.4a1.8 1.8 0 0 0 2.5 2.5l5-5a3.1 3.1 0 0 0-4.4-4.4l-5.4 5.4a4.4 4.4 0 0 0 6.2 6.2l4.3-4.3"
    fill="none" stroke="#33506e" stroke-width="1.3" stroke-linecap="round" />
</svg>`;

function toast(message: string): void {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

/* Local storage (optionally sealed by the device passphrase) */

function readVaultMeta(): VaultMeta | null {
  try {
    const raw = localStorage.getItem(VAULT_KEY);
    if (!raw) return null;
    const meta = JSON.parse(raw) as VaultMeta;
    if (meta?.v === 1 && typeof meta.salt === "string" && isVaultBlob(meta.check)) {
      return meta;
    }
  } catch {
    /* ignore */
  }
  return null;
}

function storeGet(key: string): string | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  if (vaultKey) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (isVaultBlob(parsed)) return openString(vaultKey, parsed);
    } catch {
      /* legacy plaintext */
    }
  }
  return raw;
}

function storeSet(key: string, value: string): void {
  if (vaultKey) {
    localStorage.setItem(key, JSON.stringify(sealString(vaultKey, value)));
  } else {
    localStorage.setItem(key, value);
  }
}

function loadStored(): StoredIdentity | null {
  try {
    const raw = storeGet(LS.identity);
    return raw ? (JSON.parse(raw) as StoredIdentity) : null;
  } catch {
    return null;
  }
}

function saveIdentity(rec: StoredIdentity): void {
  storeSet(LS.identity, JSON.stringify(rec));
}

function loadPreKeys(): StoredPreKeys | null {
  try {
    const raw = storeGet(LS.prekeys);
    return raw ? (JSON.parse(raw) as StoredPreKeys) : null;
  } catch {
    return null;
  }
}

function loadSession(peer: string) {
  const raw = storeGet(LS.session(peer));
  if (!raw) return null;
  try {
    return deserializeState(JSON.parse(raw));
  } catch {
    return null;
  }
}

function saveSession(peer: string, state: ReturnType<typeof deserializeState>): void {
  storeSet(LS.session(peer), JSON.stringify(serializeState(state)));
}

function historyFor(peer: string): ChatMessage[] {
  let list = histories.get(peer);
  if (!list) {
    try {
      const raw = storeGet(LS.history(peer));
      list = raw ? (JSON.parse(raw) as ChatMessage[]) : [];
    } catch {
      list = [];
    }
    histories.set(peer, list);
  }
  return list;
}

function saveHistory(peer: string): void {
  storeSet(LS.history(peer), JSON.stringify(historyFor(peer)));
}

function loadOutbox(): OutboxItem[] {
  try {
    const raw = storeGet(LS.outbox);
    return raw ? (JSON.parse(raw) as OutboxItem[]) : [];
  } catch {
    return [];
  }
}

function saveOutbox(items: OutboxItem[]): void {
  storeSet(LS.outbox, JSON.stringify(items));
}

function outboxAdd(item: OutboxItem): void {
  const items = loadOutbox();
  if (!items.some((i) => i.id === item.id)) items.push(item);
  saveOutbox(items);
}

function outboxRemove(id: string): void {
  saveOutbox(loadOutbox().filter((i) => i.id !== id));
}

function notePeerKey(peer: string, ik: string): void {
  storeSet(LS.peerKey(peer), ik);
}

function peerKeyFor(peer: string): string | null {
  return storeGet(LS.peerKey(peer));
}

function verificationFor(peer: string): { status: VerifyStatus; current: string | null } {
  const key = peerKeyFor(peer);
  if (!key || !identity) return { status: "unverified", current: null };
  const current = safetyNumber(identity.xPub, unb64(key));
  const verified = storeGet(LS.verified(peer));
  if (!verified) return { status: "unverified", current };
  return { status: verified === current ? "verified" : "changed", current };
}

async function ensurePeerKey(peer: string): Promise<string> {
  const existing = peerKeyFor(peer);
  if (existing) return existing;
  const info = await api<{ ik: string }>(`/identity/${encodeURIComponent(peer)}`);
  notePeerKey(peer, info.ik);
  return info.ik;
}

/* API */

async function api<T>(path: string, body?: unknown, auth = true): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (auth && token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`/api${path}`, {
    method: body === undefined && auth ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(data.error ?? `request failed (${res.status})`);
  return data;
}

/* Dialogs */

function openModal(html: string): HTMLDivElement {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  const dialog = document.createElement("div");
  dialog.className = "dialog";
  dialog.innerHTML = html;
  overlay.appendChild(dialog);
  document.body.appendChild(overlay);
  return overlay;
}

function closeModals(): void {
  document.querySelectorAll(".modal-overlay").forEach((el) => el.remove());
}

function showInfo(title: string, text: string): void {
  const overlay = openModal(`
    <div class="dialog-titlebar"><span>${esc(title)}</span>
      <button class="wc wc-close" type="button" data-close>&#215;</button></div>
    <div class="dialog-body">
      <p class="dialog-text">${esc(text)}</p>
      <div class="dialog-actions"><button class="msn-btn primary" type="button" data-close>OK</button></div>
    </div>`);
  overlay.querySelectorAll("[data-close]").forEach((el) => {
    el.addEventListener("click", () => overlay.remove());
  });
}

function askPassphrase(
  title: string,
  confirm: boolean,
  text: string,
): Promise<string | null> {
  return new Promise((resolve) => {
    const overlay = openModal(`
      <div class="dialog-titlebar"><span>${esc(title)}</span>
        <button class="wc wc-close" type="button" data-close>&#215;</button></div>
      <div class="dialog-body">
        <p class="dialog-text">${esc(text)}</p>
        <label class="dialog-label" for="vault-pass">Passphrase</label>
        <input id="vault-pass" type="password" autocomplete="new-password" />
        ${
          confirm
            ? `<label class="dialog-label" for="vault-pass2">Confirm passphrase</label>
               <input id="vault-pass2" type="password" autocomplete="new-password" />`
            : ""
        }
        <div class="error" id="vault-error"></div>
        <div class="dialog-actions">
          <button class="msn-btn" type="button" data-close>Cancel</button>
          <button class="msn-btn primary" type="button" id="vault-ok">OK</button>
        </div>
      </div>`);

    const pass1 = overlay.querySelector<HTMLInputElement>("#vault-pass")!;
    const pass2 = overlay.querySelector<HTMLInputElement>("#vault-pass2");
    const errorEl = overlay.querySelector<HTMLDivElement>("#vault-error")!;
    const finish = (value: string | null) => {
      overlay.remove();
      resolve(value);
    };
    overlay.querySelectorAll("[data-close]").forEach((el) => {
      el.addEventListener("click", () => finish(null));
    });
    const submit = () => {
      const a = pass1.value;
      if (a.length < 8) {
        errorEl.textContent = "Use at least 8 characters.";
        return;
      }
      if (confirm && a !== pass2?.value) {
        errorEl.textContent = "The passphrases do not match.";
        return;
      }
      finish(a);
    };
    overlay.querySelector<HTMLButtonElement>("#vault-ok")!.onclick = submit;
    overlay.querySelectorAll("input").forEach((el) => {
      el.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") submit();
      });
    });
    pass1.focus();
  });
}

function renderUnlock(meta: VaultMeta): void {
  identity = null;
  app.innerHTML = `
    <div class="desktop desktop-auth">
      <div class="msn-window signin-window">
        <div class="titlebar">
          <div class="tb-left"><span class="tb-icon"></span> blacknoir Messenger</div>
          <div class="win-controls">
            <button class="wc" type="button" tabindex="-1">&#8211;</button>
            <button class="wc" type="button" tabindex="-1">&#9633;</button>
            <button class="wc wc-close" type="button" tabindex="-1">&#215;</button>
          </div>
        </div>
        <div class="signin-hero">
          <div class="wl-orb"></div>
          <div class="wl-wordmark">blacknoir</div>
          <div class="wl-sub">Locked</div>
        </div>
        <form class="signin-body" id="unlock-form">
          <p class="tagline">
            This device is locked. Enter your passphrase to decrypt your keys and
            conversation history. It never leaves this browser.
          </p>
          <div class="field">
            <label for="passphrase">Device passphrase</label>
            <input id="passphrase" type="password" autocomplete="current-password" />
          </div>
          <div class="auth-actions">
            <button class="msn-btn primary" id="unlock" type="submit">Unlock</button>
          </div>
          <div class="error" id="unlock-error"></div>
          <div class="signin-note">
            Forgot it? The data is unrecoverable. You can erase this device and create
            a new identity.
          </div>
          <div class="auth-actions">
            <button class="msn-btn" id="wipe" type="button">Forget this device</button>
          </div>
        </form>
        <div class="signin-footer">Argon2id &#183; AES-256-GCM &#183; end-to-end encrypted</div>
      </div>
    </div>`;

  const form = document.querySelector<HTMLFormElement>("#unlock-form")!;
  const input = document.querySelector<HTMLInputElement>("#passphrase")!;
  const errorEl = document.querySelector<HTMLDivElement>("#unlock-error")!;
  const button = document.querySelector<HTMLButtonElement>("#unlock")!;

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    errorEl.textContent = "";
    button.disabled = true;
    try {
      vaultKey = await unlockVault(input.value, meta);
      await startWithStoredIdentity();
    } catch {
      vaultKey = null;
      errorEl.textContent = "Wrong passphrase.";
      button.disabled = false;
    }
  });

  document.querySelector<HTMLButtonElement>("#wipe")!.onclick = () => {
    if (!confirm("Erase this device? Keys and history cannot be recovered.")) return;
    localStorage.clear();
    location.reload();
  };

  input.focus();
}

/* Auth */

function renderAuth(error = "", prefill = ""): void {
  identity = null;
  app.innerHTML = `
    <div class="desktop desktop-auth">
      <div class="msn-window signin-window">
        <div class="titlebar">
          <div class="tb-left"><span class="tb-icon"></span> blacknoir Messenger</div>
          <div class="win-controls">
            <button class="wc" type="button" tabindex="-1">&#8211;</button>
            <button class="wc" type="button" tabindex="-1">&#9633;</button>
            <button class="wc wc-close" type="button" tabindex="-1">&#215;</button>
          </div>
        </div>
        <div class="signin-hero">
          <div class="wl-orb"></div>
          <div class="wl-wordmark">blacknoir</div>
          <div class="wl-sub">Messenger</div>
        </div>
        <div class="signin-body">
          <p class="tagline">
            Sign in to see who is online. Conversations are end-to-end encrypted and
            your keys never leave this browser.
          </p>
          <div class="field">
            <label for="username">E-mail address / username</label>
            <input id="username" maxlength="20" autocomplete="off" spellcheck="false"
              placeholder="e.g. river_stone" value="${esc(prefill)}" />
          </div>
          <div class="auth-actions">
            <button class="msn-btn primary" id="signin">Sign in</button>
            <button class="msn-btn" id="create">Create identity</button>
          </div>
          <div class="error" id="auth-error">${esc(error)}</div>
          <div class="signin-note">
            New here? Create an identity to generate an Ed25519 signing key, an X25519
            key, a signed prekey and ${OPK_COUNT} one-time prekeys on this device.
          </div>
        </div>
        <div class="signin-footer">End-to-end encrypted &#183; AES-256-GCM &#183; Double Ratchet</div>
      </div>
    </div>`;

  const username = document.querySelector<HTMLInputElement>("#username")!;
  const errorEl = document.querySelector<HTMLDivElement>("#auth-error")!;
  const disable = (on: boolean) => {
    document.querySelector<HTMLButtonElement>("#create")!.disabled = on;
    document.querySelector<HTMLButtonElement>("#signin")!.disabled = on;
  };

  document.querySelector<HTMLButtonElement>("#create")!.onclick = async () => {
    const name = username.value.trim();
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(name)) {
      errorEl.textContent = "Use 3-20 letters, digits or underscores.";
      return;
    }
    disable(true);
    errorEl.textContent = "";
    try {
      await createIdentity(name);
    } catch (err) {
      errorEl.textContent = (err as Error).message;
      disable(false);
    }
  };

  document.querySelector<HTMLButtonElement>("#signin")!.onclick = async () => {
    const stored = loadStored();
    if (!stored) {
      errorEl.textContent = "No identity on this device. Create one first.";
      return;
    }
    disable(true);
    errorEl.textContent = "";
    try {
      await signIn(stored);
    } catch (err) {
      errorEl.textContent = (err as Error).message;
      disable(false);
    }
  };

  username.focus();
}

async function createIdentity(name: string): Promise<void> {
  const id = generateIdentity();
  const spk = generateSignedPreKey(id);
  const opks = generateOneTimePreKeys(1, OPK_COUNT);
  const result = await api<{ token: string }>(
    "/register",
    {
      username: name,
      edPub: b64(id.edPub),
      ik: b64(id.xPub),
      spk: b64(spk.pub),
      spkSig: b64(spk.sig),
      opks: opks.map((o) => ({ id: o.id, pub: b64(o.pub) })),
    },
    false,
  );

  const rec: StoredIdentity = {
    username: name,
    edPriv: b64(id.edPriv),
    edPub: b64(id.edPub),
    xPriv: b64(id.xPriv),
    xPub: b64(id.xPub),
  };
  const prekeyRec: StoredPreKeys = {
    spkPriv: b64(spk.priv),
    spkPub: b64(spk.pub),
    opkPrivs: Object.fromEntries(opks.map((o) => [String(o.id), b64(o.priv)])),
  };

  storeSet(LS.prekeys, JSON.stringify(prekeyRec));
  saveIdentity(rec);
  identity = id;
  me = name;
  token = result.token;
  await enterApp();
}

async function signIn(stored: StoredIdentity): Promise<void> {
  identity = {
    edPriv: unb64(stored.edPriv),
    edPub: unb64(stored.edPub),
    xPriv: unb64(stored.xPriv),
    xPub: unb64(stored.xPub),
  };
  me = stored.username;
  const { nonce } = await api<{ nonce: string }>(
    "/challenge",
    { username: me },
    false,
  );
  const signature = sign(identity, utf8(AUTH_PREFIX + nonce));
  const result = await api<{ token: string }>(
    "/login",
    { username: me, signature: b64(signature) },
    false,
  );
  token = result.token;
  await enterApp();
}

async function startWithStoredIdentity(): Promise<void> {
  const stored = loadStored();
  if (!stored) {
    renderAuth();
    return;
  }
  try {
    await signIn(stored);
  } catch (err) {
    renderAuth((err as Error).message, stored.username);
  }
}

async function enterApp(): Promise<void> {
  buildShell();
  connect();
  await loadUsers();
  renderChat();
  void flushOutbox();
}

/* Shell */

function buildShell(): void {
  app.innerHTML = `
    <div class="desktop">
      <aside class="msn-window contacts" id="sidebar">
        <div class="titlebar">
          <div class="tb-left"><span class="tb-icon"></span> blacknoir Messenger</div>
          <div class="win-controls">
            <button class="wc" type="button" tabindex="-1">&#8211;</button>
            <button class="wc" type="button" tabindex="-1">&#9633;</button>
            <button class="wc wc-close" type="button" tabindex="-1">&#215;</button>
          </div>
        </div>
        <div class="menubar">
          <span>File</span><span>Contacts</span><span>Actions</span><span>Tools</span><span>Help</span>
        </div>
        <div class="user-card">
          <div class="dp big ${dpClass(me)}">${esc(initials(me))}</div>
          <div class="user-info">
            <div class="display-name">${esc(me)}</div>
            <div class="status-line" id="conn">${ONLINE_ICON}<span>Available</span></div>
            <div class="personal-msg">End-to-end encrypted. Always.</div>
          </div>
        </div>
        <div class="searchbar">
          <input id="search" type="search" placeholder="Find a contact or number..." autocomplete="off" />
        </div>
        <div class="users" id="users"></div>
        <div class="ad-banner">
          <div class="ad-title">End-to-end encrypted</div>
          <div class="ad-sub">AES-256-GCM &#183; X3DH &#183; Double Ratchet</div>
        </div>
        <div class="contacts-foot">
          <button class="msn-btn small" id="refresh" type="button">Refresh</button>
          <button class="msn-btn small" id="alerts" type="button">Alerts</button>
          <button class="msn-btn small" id="lock" type="button">Lock</button>
          <button class="msn-btn small" id="forget" type="button">Forget device</button>
        </div>
      </aside>
      <main class="msn-window conversation" id="conversation">
        <div class="titlebar">
          <div class="tb-left"><span class="tb-icon"></span> <span id="conv-title">Conversation</span></div>
          <div class="win-controls">
            <button class="wc" type="button" tabindex="-1">&#8211;</button>
            <button class="wc" type="button" tabindex="-1">&#9633;</button>
            <button class="wc wc-close" type="button" tabindex="-1">&#215;</button>
          </div>
        </div>
        <div class="menubar">
          <span>File</span><span>Edit</span><span>Actions</span><span>Tools</span><span>Help</span>
        </div>
        <div class="conv-strip" id="chat-head"></div>
        <div class="messages" id="messages"></div>
        <div class="composer-wrap">
          <div class="format-toolbar">
            <button class="fmt" type="button" tabindex="-1" title="Bold"><b>B</b></button>
            <button class="fmt" type="button" tabindex="-1" title="Italic"><i>I</i></button>
            <button class="fmt" type="button" tabindex="-1" title="Emoticon">&#9786;</button>
            <button class="fmt attach-btn" type="button" id="attach" title="Send a file">${PAPERCLIP}</button>
          </div>
          <div class="pending-file" id="pending-file" hidden></div>
          <form class="composer" id="composer">
            <textarea id="input" rows="3" placeholder="Type a message..." autocomplete="off"></textarea>
            <button class="msn-btn send" id="send" type="submit">Send</button>
          </form>
          <input type="file" id="file-input" hidden />
        </div>
      </main>
    </div>`;

  document.querySelector<HTMLButtonElement>("#refresh")!.onclick = () => {
    void loadUsers();
  };
  document.querySelector<HTMLButtonElement>("#forget")!.onclick = () => {
    if (!confirm("Delete this identity and all local sessions on this device?")) return;
    localStorage.clear();
    location.reload();
  };
  document.querySelector<HTMLButtonElement>("#lock")!.onclick = () => {
    if (readVaultMeta()) {
      vaultKey = null;
      socket?.close();
      location.reload();
    } else {
      void setPassphrase();
    }
  };
  document.querySelector<HTMLButtonElement>("#alerts")!.onclick = () => {
    void enableNotifications();
  };
  updateLockButton();

  document.querySelector<HTMLDivElement>("#users")!.addEventListener("click", (ev) => {
    const target = (ev.target as HTMLElement).closest<HTMLElement>("[data-peer]");
    if (!target) return;
    selectPeer(target.dataset.peer!);
  });

  const search = document.querySelector<HTMLInputElement>("#search")!;
  search.value = searchTerm;
  search.addEventListener("input", () => {
    searchTerm = search.value.trim().toLowerCase();
    renderUsers();
  });

  const input = document.querySelector<HTMLTextAreaElement>("#input")!;
  input.addEventListener("input", () => {
    if (!activePeer || !socket || socket.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    if (now - lastTypingSent < 2200) return;
    lastTypingSent = now;
    socket.send(JSON.stringify({ type: "typing", to: activePeer }));
  });

  document.querySelector<HTMLFormElement>("#composer")!.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void sendCurrent();
  });
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      document.querySelector<HTMLFormElement>("#composer")?.requestSubmit();
    }
  });

  const fileInput = document.querySelector<HTMLInputElement>("#file-input")!;
  document.querySelector<HTMLButtonElement>("#attach")!.onclick = () => fileInput.click();
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    fileInput.value = "";
    if (!file) return;
    if (file.size > MAX_FILE) {
      toast("File is too large (max 8 MB).");
      return;
    }
    pendingFile = file;
    updatePendingFile();
    input.focus();
  });

  setConnection(false);
}

function updateLockButton(): void {
  const button = document.getElementById("lock");
  if (button) button.textContent = readVaultMeta() ? "Lock" : "Set passphrase";
}

function updatePendingFile(): void {
  const el = document.getElementById("pending-file");
  if (!el) return;
  if (!pendingFile) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  el.innerHTML = `${PAPERCLIP}<span class="chip-name">${esc(pendingFile.name)}</span>
    <span class="chip-size">${fileSize(pendingFile.size)}</span>
    <button class="chip-x" type="button" id="chip-x">&#215;</button>`;
  document.querySelector<HTMLButtonElement>("#chip-x")!.onclick = () => {
    pendingFile = null;
    updatePendingFile();
  };
}

async function setPassphrase(): Promise<void> {
  const passphrase = await askPassphrase(
    "Set a device passphrase",
    true,
    "Your identity keys, sessions and chat history will be encrypted on this device with Argon2id and AES-256-GCM. There is no recovery if you forget it.",
  );
  if (!passphrase) return;
  const { key, meta } = await createVault(passphrase);
  const plain: [string, string][] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && k.startsWith("blacknoir.") && k !== VAULT_KEY) {
      const v = localStorage.getItem(k);
      if (v !== null) plain.push([k, v]);
    }
  }
  vaultKey = key;
  for (const [k, v] of plain) {
    localStorage.setItem(k, JSON.stringify(sealString(key, v)));
  }
  localStorage.setItem(VAULT_KEY, JSON.stringify(meta));
  updateLockButton();
  toast("Passphrase set. Use Lock to lock this device.");
}

async function enableNotifications(): Promise<void> {
  if (!("Notification" in window)) {
    toast("This browser does not support notifications.");
    return;
  }
  if (Notification.permission === "granted") {
    toast("Notifications are already enabled.");
    return;
  }
  const permission = await Notification.requestPermission();
  toast(
    permission === "granted"
      ? "Notifications enabled."
      : "Notifications were not enabled.",
  );
}

function setConnection(on: boolean): void {
  connected = on;
  const el = document.getElementById("conn");
  if (el) {
    el.innerHTML = `${ONLINE_ICON}<span>${on ? "Available" : "Connecting..."}</span>`;
  }
  if (document.getElementById("messages")) renderChat();
}

/* Contacts */

async function loadUsers(): Promise<void> {
  try {
    const data = await api<{ users: { username: string }[] }>("/users");
    users = data.users.map((u) => u.username).filter((u) => u !== me);
    renderUsers();
  } catch (err) {
    console.warn(err);
  }
}

function contactRow(u: string, online: boolean): string {
  return `
    <button class="user${u === activePeer ? " active" : ""}" data-peer="${esc(u)}" type="button">
      ${online ? ONLINE_ICON : OFFLINE_ICON}
      <div class="dp small ${dpClass(u)}">${esc(initials(u))}</div>
      <span class="user-name">${esc(u)}</span>
    </button>`;
}

function renderUsers(): void {
  const el = document.getElementById("users");
  if (!el) return;
  const filtered = users.filter((u) => u.toLowerCase().includes(searchTerm));
  const online = filtered.filter((u) => onlineUsers.has(u));
  const offline = filtered.filter((u) => !onlineUsers.has(u));

  let body = `<div class="group-head"><span class="caret">&#9662;</span> Online (${online.length})</div>`;
  if (online.length > 0) body += online.map((u) => contactRow(u, true)).join("");
  else if (users.length === 0) {
    body += `<div class="users-empty">Nobody else is here yet. Open blacknoir in another browser profile and create a second identity.</div>`;
  } else if (filtered.length === 0) {
    body += `<div class="users-empty">No contacts match your search.</div>`;
  } else {
    body += `<div class="users-empty">No one is online right now.</div>`;
  }

  body += `<div class="group-head offline"><span class="caret">&#9662;</span> Offline (${offline.length})</div>`;
  if (offline.length > 0) body += offline.map((u) => contactRow(u, false)).join("");

  el.innerHTML = body;
}

function selectPeer(peer: string): void {
  activePeer = peer;
  pendingFile = null;
  updatePendingFile();
  renderUsers();
  renderChat();
  document.getElementById("sidebar")?.classList.add("has-active");
  document.querySelector<HTMLTextAreaElement>("#input")?.focus();
}

/* Conversation */

function peerStatus(peer: string): string {
  if (typing && typing.peer === peer && typing.until > Date.now()) {
    return `${peer} is typing...`;
  }
  if (!connected) return "Connecting...";
  return onlineUsers.has(peer) ? "Available" : "Offline";
}

function verifyBadge(peer: string): string {
  const { status } = verificationFor(peer);
  if (status === "verified") {
    return `<button class="verify-badge verified" id="verify" type="button">Verified</button>`;
  }
  if (status === "changed") {
    return `<button class="verify-badge changed" id="verify" type="button">Code changed</button>`;
  }
  return `<button class="verify-badge" id="verify" type="button">Verify</button>`;
}

function renderChat(): void {
  const head = document.getElementById("chat-head");
  const messages = document.getElementById("messages");
  const composer = document.getElementById("composer") as HTMLFormElement | null;
  const input = document.getElementById("input") as HTMLTextAreaElement | null;
  const send = document.getElementById("send") as HTMLButtonElement | null;
  const convTitle = document.getElementById("conv-title");
  if (!head || !messages || !composer || !input || !send) return;

  const conv = document.getElementById("conversation");
  conv?.classList.toggle("is-open", Boolean(activePeer));

  if (!activePeer) {
    if (convTitle) convTitle.textContent = "Conversation";
    head.innerHTML = `
      <div class="dp ${dpClass("blacknoir")}">BN</div>
      <div class="conv-meta">
        <div class="conv-name">blacknoir</div>
        <div class="conv-status">AES-256-GCM &#183; Double Ratchet</div>
      </div>
      <div class="badge-e2e">encrypted</div>`;
    messages.innerHTML = `
      <div class="msg system">
        Pick a contact from your list to start a conversation. Every message gets its
        own key through a Double Ratchet, and the relay only sees ciphertext.
      </div>`;
    composer.style.display = "none";
    return;
  }

  composer.style.display = "flex";
  if (convTitle) convTitle.textContent = `${activePeer} - Conversation`;
  head.innerHTML = `
    <button class="msn-btn small back" id="back" type="button">Back</button>
    <div class="dp ${dpClass(activePeer)}">${esc(initials(activePeer))}</div>
    <div class="conv-meta">
      <div class="conv-name">${esc(activePeer)}</div>
      <div class="conv-status">${
        onlineUsers.has(activePeer) ? ONLINE_ICON : OFFLINE_ICON
      }<span>${esc(peerStatus(activePeer))}</span></div>
    </div>
    ${verifyBadge(activePeer)}`;
  document.querySelector<HTMLButtonElement>("#back")!.onclick = () => {
    document.getElementById("sidebar")?.classList.remove("has-active");
  };
  document.querySelector<HTMLButtonElement>("#verify")!.onclick = () => {
    void openVerification(activePeer!);
  };

  const list = historyFor(activePeer);
  messages.innerHTML = "";
  if (list.length === 0) {
    messages.innerHTML = `<div class="msg system">You have just opened a conversation with <b>${esc(
      activePeer,
    )}</b>. Messages are end-to-end encrypted. Say hello.</div>`;
  } else {
    for (const m of list) {
      const div = document.createElement("div");
      if (m.from === "system") {
        div.className = "msg system";
        div.textContent = m.text;
      } else {
        const mine = m.from === me;
        div.className = `msg ${mine ? "mine" : "theirs"}`;
        const msgHead = document.createElement("div");
        msgHead.className = "msg-head";
        const name = document.createElement("span");
        name.className = "msg-name";
        name.textContent = mine ? me : activePeer;
        const said = document.createTextNode(" says: ");
        const time = document.createElement("span");
        time.className = "msg-time";
        time.textContent = `(${formatTime(m.ts)})`;
        msgHead.append(name, said, time);
        if (mine && m.status) {
          const st = document.createElement("span");
          st.className = `msg-status ${m.status}`;
          st.textContent = statusLabel(m.status);
          msgHead.appendChild(st);
        }
        div.appendChild(msgHead);
        if (m.file) div.appendChild(attachmentNode(m.file));
        if (m.text) {
          const text = document.createElement("div");
          text.className = "msg-text";
          text.textContent = m.text;
          div.appendChild(text);
        }
      }
      messages.appendChild(div);
    }
  }
  messages.scrollTop = messages.scrollHeight;
  input.placeholder = `Type a message to ${activePeer}...`;
  input.focus();
}

/* Attachments */

async function uploadAttachment(file: File, peer: string): Promise<Attachment> {
  const data = new Uint8Array(await file.arrayBuffer());
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const ciphertext = await aesGcmEncrypt(key, iv, data, new Uint8Array(0));
  const res = await fetch(`/api/blob?to=${encodeURIComponent(peer)}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/octet-stream",
    },
    body: ab(ciphertext),
  });
  const info = (await res.json().catch(() => ({}))) as { id?: string; error?: string };
  if (!res.ok || !info.id) throw new Error(info.error ?? "upload failed");
  return {
    id: info.id,
    key: b64(key),
    iv: b64(iv),
    name: file.name,
    mime: file.type || "application/octet-stream",
    size: file.size,
  };
}

async function fetchAttachment(att: Attachment): Promise<Blob> {
  const res = await fetch(`/api/blob/${att.id}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("attachment unavailable");
  const ciphertext = new Uint8Array(await res.arrayBuffer());
  const plain = await aesGcmDecrypt(
    unb64(att.key),
    unb64(att.iv),
    ciphertext,
    new Uint8Array(0),
  );
  return new Blob([plain.slice().buffer], { type: att.mime });
}

async function loadAttachment(att: Attachment): Promise<void> {
  if (attachCache.has(att.id) || attachPending.has(att.id)) return;
  attachPending.add(att.id);
  try {
    const blob = await fetchAttachment(att);
    attachCache.set(att.id, URL.createObjectURL(blob));
    if (activePeer) renderChat();
  } catch (err) {
    console.warn("attachment failed", err);
    toast("Could not download the attachment.");
  } finally {
    attachPending.delete(att.id);
  }
}

function attachmentNode(att: Attachment): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "attachment";
  const url = attachCache.get(att.id);

  if (url) {
    if (att.mime.startsWith("image/")) {
      const img = document.createElement("img");
      img.className = "attach-img";
      img.src = url;
      img.alt = att.name;
      img.title = att.name;
      wrap.appendChild(img);
    } else {
      const a = document.createElement("a");
      a.className = "attach-file";
      a.href = url;
      a.download = att.name;
      a.textContent = `Download ${att.name} (${fileSize(att.size)})`;
      wrap.appendChild(a);
    }
    return wrap;
  }

  const button = document.createElement("button");
  button.className = "attach-file";
  button.type = "button";
  const isImage = att.mime.startsWith("image/");
  button.textContent = attachPending.has(att.id)
    ? `Decrypting ${att.name}...`
    : isImage
      ? `Load image ${att.name} (${fileSize(att.size)})`
      : `Download ${att.name} (${fileSize(att.size)})`;
  button.onclick = () => {
    void loadAttachment(att);
  };
  wrap.appendChild(button);
  if (isImage) void loadAttachment(att);
  return wrap;
}

/* Verification */

async function openVerification(peer: string): Promise<void> {
  if (!identity) return;
  let key: string;
  try {
    key = await ensurePeerKey(peer);
  } catch {
    toast("Could not load their identity key.");
    return;
  }
  const current = safetyNumber(identity.xPub, unb64(key));
  const verified = storeGet(LS.verified(peer));
  const changed = verified !== null && verified !== current;
  const groups = current.split(" ");
  const a = groups.slice(0, 3).join(" ");
  const b = groups.slice(3).join(" ");

  const overlay = openModal(`
    <div class="dialog-titlebar"><span>Verify ${esc(peer)}</span>
      <button class="wc wc-close" type="button" data-close>&#215;</button></div>
    <div class="dialog-body">
      <p class="dialog-text">
        Compare this code with ${esc(peer)} over a call or in person. If both devices
        show the same code, nobody is sitting in the middle of your conversation.
      </p>
      <div class="safety-number">${a}<br />${b}</div>
      ${
        changed
          ? `<div class="warning">This code changed since you last verified. Only verify if you know why.</div>`
          : ""
      }
      <div class="dialog-actions">
        <button class="msn-btn" type="button" data-close>Close</button>
        <button class="msn-btn primary" type="button" id="mark-verified">${
          changed ? "Verify new code" : "I have verified this code"
        }</button>
      </div>
    </div>`);

  overlay.querySelectorAll("[data-close]").forEach((el) => {
    el.addEventListener("click", () => overlay.remove());
  });
  overlay.querySelector<HTMLButtonElement>("#mark-verified")!.onclick = () => {
    storeSet(LS.verified(peer), current);
    overlay.remove();
    toast(`${peer} marked as verified.`);
    renderChat();
    renderUsers();
  };
}

/* Messages */

function decodeInner(text: string): InnerMessage {
  try {
    const parsed = JSON.parse(text) as InnerMessage;
    if (parsed && (parsed.kind === "text" || parsed.kind === "file")) return parsed;
  } catch {
    /* legacy plaintext */
  }
  return { kind: "text", text };
}

function addMessage(peer: string, message: ChatMessage): void {
  historyFor(peer).push(message);
  saveHistory(peer);
  if (peer === activePeer) renderChat();
}

function updateMessage(peer: string, id: string, patch: Partial<ChatMessage>): void {
  const list = historyFor(peer);
  const msg = list.find((m) => m.id === id);
  if (!msg) return;
  Object.assign(msg, patch);
  saveHistory(peer);
  if (peer === activePeer) renderChat();
}

function updateMessageAnywhere(id: string, patch: Partial<ChatMessage>): void {
  for (const [peer, list] of histories) {
    const msg = list.find((m) => m.id === id);
    if (!msg) continue;
    Object.assign(msg, patch);
    saveHistory(peer);
    if (peer === activePeer) renderChat();
    return;
  }
}

function handleReceipt(ids: string[]): void {
  const set = new Set(ids);
  for (const [peer, list] of histories) {
    let changed = false;
    for (const m of list) {
      if (m.id && set.has(m.id) && m.status !== "delivered") {
        m.status = "delivered";
        changed = true;
      }
    }
    if (changed) {
      saveHistory(peer);
      if (peer === activePeer) renderChat();
    }
  }
}

async function buildWire(peer: string, inner: InnerMessage): Promise<string> {
  if (!identity) throw new Error("no identity");
  const existing = loadSession(peer);
  let payload: WirePayload;
  const plaintext = JSON.stringify(inner);

  if (!existing) {
    const bundle = await api<PreKeyBundle>(`/prekey/${encodeURIComponent(peer)}`);
    notePeerKey(peer, bundle.ik);
    const started = await startInitiator(identity, bundle);
    const out = await ratchetEncrypt(started.state, plaintext);
    saveSession(peer, out.state);
    payload = {
      type: "prekey",
      init: started.init,
      header: { dh: b64(out.header.dh), pn: out.header.pn, n: out.header.n },
      ciphertext: b64(out.ciphertext),
    };
  } else {
    const out = await ratchetEncrypt(existing, plaintext);
    saveSession(peer, out.state);
    payload = {
      type: "msg",
      header: { dh: b64(out.header.dh), pn: out.header.pn, n: out.header.n },
      ciphertext: b64(out.ciphertext),
    };
  }
  return b64(utf8(JSON.stringify(payload)));
}

async function sendCurrent(): Promise<void> {
  const input = document.getElementById("input") as HTMLTextAreaElement | null;
  if (!input || !activePeer || !identity) return;
  const peer = activePeer;
  const text = input.value.trim();
  const file = pendingFile;
  if (!text && !file) return;

  input.value = "";
  pendingFile = null;
  updatePendingFile();

  const id = crypto.randomUUID();
  addMessage(peer, { id, from: me, text, ts: Date.now(), status: "sending" });

  try {
    let attachment: Attachment | undefined;
    if (file) {
      attachment = await uploadAttachment(file, peer);
      updateMessage(peer, id, { file: attachment });
    }
    const payload = await buildWire(peer, {
      kind: attachment ? "file" : "text",
      text,
      file: attachment,
    });
    try {
      await api("/send", { to: peer, payload, cid: id });
      updateMessage(peer, id, { status: "sent" });
    } catch (err) {
      if (err instanceof TypeError) {
        outboxAdd({ id, peer, payload, ts: Date.now() });
        updateMessage(peer, id, { status: "queued" });
      } else {
        throw err;
      }
    }
  } catch (err) {
    updateMessage(peer, id, { status: "failed" });
    addMessage(peer, {
      from: "system",
      text: `Could not send: ${(err as Error).message}`,
      ts: Date.now(),
    });
  }
}

async function flushOutbox(): Promise<void> {
  if (flushing) return;
  flushing = true;
  try {
    for (const item of loadOutbox()) {
      try {
        await api("/send", { to: item.peer, payload: item.payload, cid: item.id });
        outboxRemove(item.id);
        updateMessageAnywhere(item.id, { status: "sent" });
      } catch (err) {
        if (err instanceof TypeError) break;
        outboxRemove(item.id);
        updateMessageAnywhere(item.id, { status: "failed" });
      }
    }
  } finally {
    flushing = false;
  }
}

/* Socket */

function connect(): void {
  socket?.close();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(
    `${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`,
  );
  socket = ws;

  ws.onopen = () => {
    setConnection(true);
    void flushOutbox();
  };
  ws.onclose = (ev) => {
    setConnection(false);
    if (ev.code === 4001) {
      renderAuth("Your session expired. Sign in again.", me);
      return;
    }
    setTimeout(() => {
      if (token) connect();
    }, 2000);
  };
  ws.onmessage = (ev) => {
    let data: {
      type?: string;
      messages?: Envelope[];
      ids?: string[];
      users?: string[];
      from?: string;
    };
    try {
      data = JSON.parse(String(ev.data));
    } catch {
      return;
    }
    if (data.type === "messages" && data.messages) {
      enqueue(data.messages);
    } else if (data.type === "receipt" && data.ids) {
      handleReceipt(data.ids);
    } else if (data.type === "presence" && data.users) {
      onlineUsers = new Set(data.users);
      renderUsers();
      renderChat();
    } else if (data.type === "typing" && data.from) {
      handleTyping(data.from);
    }
  };
}

function handleTyping(from: string): void {
  if (from !== activePeer) return;
  typing = { peer: from, until: Date.now() + 4200 };
  renderChat();
  setTimeout(() => {
    if (typing && typing.until <= Date.now()) {
      typing = null;
      renderChat();
    }
  }, 4400);
}

function enqueue(envs: Envelope[]): void {
  decryptQueue = decryptQueue
    .then(() => processEnvelopes(envs))
    .catch((err) => console.error("decrypt queue", err));
}

async function processEnvelopes(envs: Envelope[]): Promise<void> {
  const ids: string[] = [];
  for (const env of envs) {
    ids.push(env.id);
    try {
      await handleEnvelope(env);
    } catch (err) {
      console.warn("could not decrypt message", err);
    }
  }
  if (ids.length > 0) {
    api("/ack", { ids }).catch((err) => console.warn("ack failed", err));
  }
}

async function handleEnvelope(env: Envelope): Promise<void> {
  if (!identity) throw new Error("no identity");
  const payload = JSON.parse(fromUtf8(unb64(env.payload))) as WirePayload;
  const header: RatchetHeader = {
    dh: unb64(payload.header.dh),
    pn: payload.header.pn,
    n: payload.header.n,
  };
  const ciphertext = unb64(payload.ciphertext);
  const existing = loadSession(env.from);

  if (existing) {
    const opened = await ratchetDecrypt(existing, header, ciphertext);
    saveSession(env.from, opened.state);
    receiveMessage(env, opened.plaintext);
    return;
  }

  if (payload.type !== "prekey" || !payload.init) {
    throw new Error("message before handshake");
  }
  notePeerKey(env.from, payload.init.ik);
  const pre = loadPreKeys();
  if (!pre) throw new Error("missing local prekeys");
  const opkPriv =
    payload.init.opkId !== undefined ? pre.opkPrivs[String(payload.init.opkId)] : undefined;
  const state = await acceptResponder(
    identity,
    unb64(pre.spkPriv),
    unb64(pre.spkPub),
    opkPriv ? unb64(opkPriv) : undefined,
    payload.init,
    header.dh,
  );
  const opened = await ratchetDecrypt(state, header, ciphertext);
  saveSession(env.from, opened.state);
  receiveMessage(env, opened.plaintext);
}

function receiveMessage(env: Envelope, plaintext: string): void {
  const inner = decodeInner(plaintext);
  addMessage(env.from, {
    from: env.from,
    text: inner.text ?? "",
    ts: env.ts,
    file: inner.file,
  });
  notify(env.from, inner);
}

function notify(from: string, inner: InnerMessage): void {
  if (!("Notification" in window)) return;
  if (Notification.permission !== "granted" || !document.hidden) return;
  const body = inner.kind === "file" ? "Sent you an attachment" : "Sent you a message";
  try {
    const n = new Notification(`${from} says`, {
      body,
      tag: `blacknoir-${from}`,
      icon: "/icons/icon-192.png",
    });
    n.onclick = () => {
      window.focus();
      selectPeer(from);
      n.close();
    };
  } catch {
    /* notifications unavailable */
  }
}

/* Boot */

async function boot(): Promise<void> {
  const meta = readVaultMeta();
  if (meta) {
    renderUnlock(meta);
    return;
  }
  await startWithStoredIdentity();
}

window.addEventListener("online", () => {
  void flushOutbox();
});

if ("serviceWorker" in navigator && import.meta.env.PROD) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* offline support unavailable */
    });
  });
}

void boot();
