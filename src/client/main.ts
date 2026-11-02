import "./style.css";
import {
  acceptResponder,
  b64,
  deserializeState,
  fromUtf8,
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  ratchetDecrypt,
  ratchetEncrypt,
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

const AUTH_PREFIX = "blacknoir-Auth:";
const OPK_COUNT = 20;

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

interface ChatMessage {
  from: string;
  text: string;
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

const LS = {
  identity: "blacknoir.identity",
  prekeys: "blacknoir.prekeys",
  session: (peer: string) => `blacknoir.session.${peer}`,
  history: (peer: string) => `blacknoir.history.${peer}`,
};

let identity: Identity | null = null;
let me = "";
let token = "";
let socket: WebSocket | null = null;
let activePeer: string | null = null;
let users: string[] = [];
let connected = false;
let decryptQueue: Promise<void> = Promise.resolve();

const histories = new Map<string, ChatMessage[]>();
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

function loadStored(): StoredIdentity | null {
  try {
    const raw = localStorage.getItem(LS.identity);
    return raw ? (JSON.parse(raw) as StoredIdentity) : null;
  } catch {
    return null;
  }
}

function saveIdentity(rec: StoredIdentity): void {
  localStorage.setItem(LS.identity, JSON.stringify(rec));
}

function loadPreKeys(): StoredPreKeys | null {
  try {
    const raw = localStorage.getItem(LS.prekeys);
    return raw ? (JSON.parse(raw) as StoredPreKeys) : null;
  } catch {
    return null;
  }
}

function loadSession(peer: string) {
  const raw = localStorage.getItem(LS.session(peer));
  if (!raw) return null;
  try {
    return deserializeState(JSON.parse(raw));
  } catch {
    return null;
  }
}

function saveSession(peer: string, state: ReturnType<typeof deserializeState>): void {
  localStorage.setItem(LS.session(peer), JSON.stringify(serializeState(state)));
}

function historyFor(peer: string): ChatMessage[] {
  let list = histories.get(peer);
  if (!list) {
    try {
      const raw = localStorage.getItem(LS.history(peer));
      list = raw ? (JSON.parse(raw) as ChatMessage[]) : [];
    } catch {
      list = [];
    }
    histories.set(peer, list);
  }
  return list;
}

function saveHistory(peer: string): void {
  localStorage.setItem(LS.history(peer), JSON.stringify(historyFor(peer)));
}

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

function renderAuth(error = "", prefill = ""): void {
  identity = null;
  app.innerHTML = `
    <div class="auth">
      <div class="auth-card">
        <div class="brand">
          <div class="brand-mark">B</div>
          <h1>blacknoir</h1>
        </div>
        <p class="tagline">
          End-to-end encrypted messaging. Your keys are generated in this browser and
          never leave it. The relay only sees ciphertext.
        </p>
        <div class="field">
          <label for="username">Choose a username</label>
          <input id="username" maxlength="20" autocomplete="off" spellcheck="false"
            placeholder="e.g. river_stone" value="${esc(prefill)}" />
        </div>
        <div class="auth-actions">
          <button class="primary" id="create">Create identity</button>
          <button id="signin">Sign in</button>
        </div>
        <div class="error" id="auth-error">${esc(error)}</div>
        <div class="hint">
          Creating an identity generates an Ed25519 signing key, an X25519 key, a signed
          prekey and ${OPK_COUNT} one-time prekeys. Messages use the Double Ratchet with
          AES-256-GCM. This device stores your private keys in local storage.
        </div>
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

  localStorage.setItem(LS.prekeys, JSON.stringify(prekeyRec));
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

async function enterApp(): Promise<void> {
  buildShell();
  connect();
  await loadUsers();
  renderChat();
}

function buildShell(): void {
  app.innerHTML = `
    <div class="app">
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-head">
          <div class="avatar">${esc(initials(me))}</div>
          <div class="me">
            <div class="name">${esc(me)}</div>
            <div class="sub" id="conn"><span class="dot"></span> connecting</div>
          </div>
        </div>
        <div class="users" id="users"></div>
        <div class="sidebar-foot">
          <button class="ghost" id="refresh">Refresh</button>
          <button class="ghost" id="forget">Forget device</button>
        </div>
      </aside>
      <main class="chat">
        <div class="chat-head" id="chat-head"></div>
        <div class="messages" id="messages"></div>
        <form class="composer" id="composer">
          <input id="input" placeholder="Write an encrypted message..." autocomplete="off" />
          <button class="primary" id="send" type="submit">Send</button>
        </form>
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
  document.querySelector<HTMLDivElement>("#users")!.addEventListener("click", (ev) => {
    const target = (ev.target as HTMLElement).closest<HTMLElement>("[data-peer]");
    if (!target) return;
    selectPeer(target.dataset.peer!);
  });
  document.querySelector<HTMLFormElement>("#composer")!.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void sendCurrent();
  });
  setConnection(false);
}

function setConnection(on: boolean): void {
  connected = on;
  const el = document.getElementById("conn");
  if (!el) return;
  el.innerHTML = `<span class="dot${on ? " on" : ""}"></span>${
    on ? "connected end-to-end" : "reconnecting"
  }`;
}

async function loadUsers(): Promise<void> {
  try {
    const data = await api<{ users: { username: string }[] }>("/users");
    users = data.users.map((u) => u.username).filter((u) => u !== me);
    renderUsers();
  } catch (err) {
    console.warn(err);
  }
}

function renderUsers(): void {
  const el = document.getElementById("users");
  if (!el) return;
  if (users.length === 0) {
    el.innerHTML = `<div class="users-head">People</div><div class="empty" style="font-size:13px">Nobody else has joined yet. Open blacknoir in another browser profile and create a second identity.</div>`;
    return;
  }
  el.innerHTML =
    `<div class="users-head">People (${users.length})</div>` +
    users
      .map(
        (u) => `
        <button class="user${u === activePeer ? " active" : ""}" data-peer="${esc(u)}">
          <div class="avatar">${esc(initials(u))}</div>
          <div class="user-name">${esc(u)}</div>
        </button>`,
      )
      .join("");
}

function selectPeer(peer: string): void {
  activePeer = peer;
  renderUsers();
  renderChat();
  document.getElementById("sidebar")?.classList.add("has-active");
  document.querySelector<HTMLInputElement>("#input")?.focus();
}

function renderChat(): void {
  const head = document.getElementById("chat-head");
  const messages = document.getElementById("messages");
  const composer = document.getElementById("composer") as HTMLFormElement | null;
  const input = document.getElementById("input") as HTMLInputElement | null;
  const send = document.getElementById("send") as HTMLButtonElement | null;
  if (!head || !messages || !composer || !input || !send) return;

  if (!activePeer) {
    head.innerHTML = `<div class="title">blacknoir</div><div class="badge">AES-256-GCM</div>`;
    messages.innerHTML = `
      <div class="empty">
        <strong>Pick a conversation.</strong><br />
        Every message gets its own key through a Double Ratchet. The server relays
        ciphertext and never holds a key.
      </div>`;
    composer.style.display = "none";
    return;
  }

  composer.style.display = "flex";
  head.innerHTML = `
    <button class="ghost back" id="back" type="button">Back</button>
    <div class="avatar">${esc(initials(activePeer))}</div>
    <div>
      <div class="title">${esc(activePeer)}</div>
      <div class="status">${connected ? "encrypted channel ready" : "offline — will reconnect"}</div>
    </div>
    <div class="badge">end-to-end</div>`;
  document.querySelector<HTMLButtonElement>("#back")!.onclick = () => {
    document.getElementById("sidebar")?.classList.remove("has-active");
  };

  const list = historyFor(activePeer);
  if (list.length === 0) {
    messages.innerHTML = `<div class="empty"><strong>No messages yet.</strong><br />Say hello. The first message performs an X3DH handshake and sets up the ratchet.</div>`;
  } else {
    messages.innerHTML = "";
    for (const m of list) {
      const div = document.createElement("div");
      if (m.from === "system") {
        div.className = "msg theirs";
        const span = document.createElement("span");
        span.className = "verifying";
        span.textContent = m.text;
        div.appendChild(span);
      } else {
        div.className = `msg ${m.from === me ? "mine" : "theirs"}`;
        const text = document.createElement("div");
        text.textContent = m.text;
        const meta = document.createElement("div");
        meta.className = "meta";
        meta.textContent = new Date(m.ts).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        });
        div.append(text, meta);
      }
      messages.appendChild(div);
    }
  }
  messages.scrollTop = messages.scrollHeight;
  input.placeholder = `Message ${activePeer}...`;
  input.focus();
}

function addMessage(peer: string, message: ChatMessage): void {
  historyFor(peer).push(message);
  saveHistory(peer);
  if (peer === activePeer) renderChat();
}

function connect(): void {
  socket?.close();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(
    `${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`,
  );
  socket = ws;

  ws.onopen = () => setConnection(true);
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
    try {
      const data = JSON.parse(String(ev.data)) as {
        type: string;
        messages?: Envelope[];
      };
      if (data.type === "messages" && data.messages) enqueue(data.messages);
    } catch (err) {
      console.warn("bad ws frame", err);
    }
  };
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
    addMessage(env.from, { from: env.from, text: opened.plaintext, ts: env.ts });
    return;
  }

  if (payload.type !== "prekey" || !payload.init) {
    throw new Error("message before handshake");
  }
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
  addMessage(env.from, { from: env.from, text: opened.plaintext, ts: env.ts });
}

async function sendCurrent(): Promise<void> {
  const input = document.getElementById("input") as HTMLInputElement | null;
  if (!input || !activePeer || !identity) return;
  const text = input.value.trim();
  if (!text) return;
  const peer = activePeer;
  input.value = "";
  try {
    await sendText(peer, text);
    addMessage(peer, { from: me, text, ts: Date.now() });
  } catch (err) {
    addMessage(peer, {
      from: "system",
      text: `Could not send: ${(err as Error).message}`,
      ts: Date.now(),
    });
  }
}

async function sendText(peer: string, text: string): Promise<void> {
  if (!identity) throw new Error("no identity");
  const existing = loadSession(peer);
  let payload: WirePayload;

  if (!existing) {
    const bundle = await api<PreKeyBundle>(`/prekey/${encodeURIComponent(peer)}`);
    const started = await startInitiator(identity, bundle);
    const out = await ratchetEncrypt(started.state, text);
    saveSession(peer, out.state);
    payload = {
      type: "prekey",
      init: started.init,
      header: { dh: b64(out.header.dh), pn: out.header.pn, n: out.header.n },
      ciphertext: b64(out.ciphertext),
    };
  } else {
    const out = await ratchetEncrypt(existing, text);
    saveSession(peer, out.state);
    payload = {
      type: "msg",
      header: { dh: b64(out.header.dh), pn: out.header.pn, n: out.header.n },
      ciphertext: b64(out.ciphertext),
    };
  }

  const encoded = b64(utf8(JSON.stringify(payload)));
  await api("/send", { to: peer, payload: encoded });
}

async function boot(): Promise<void> {
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

void boot();
