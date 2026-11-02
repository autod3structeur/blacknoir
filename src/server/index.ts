import { createServer } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { WebSocketServer, type WebSocket } from "ws";
import { b64, unb64, utf8, verify, verifyPreKey } from "../crypto/index.ts";
import { Store, type Envelope, type StoredUser } from "./store.ts";

const PORT = Number(process.env.PORT ?? 8787);
const AUTH_PREFIX = "blacknoir-Auth:";
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const MAX_PAYLOAD = 128 * 1024;
const MAX_OPKS = 100;

const store = new Store();
const tokens = new Map<string, string>();
const challenges = new Map<string, { nonce: string; expires: number }>();
const sockets = new Map<string, Set<WebSocket>>();

function onlineUsers(): string[] {
  return [...sockets.entries()].filter(([, set]) => set.size > 0).map(([user]) => user);
}

function broadcast(frame: unknown): void {
  const data = JSON.stringify(frame);
  for (const set of sockets.values()) {
    for (const ws of set) {
      if (ws.readyState === ws.OPEN) ws.send(data);
    }
  }
}

function broadcastPresence(): void {
  broadcast({ type: "presence", users: onlineUsers() });
}

function isB64(v: unknown, length?: number): v is string {
  if (typeof v !== "string" || v.length > 512) return false;
  try {
    const bytes = unb64(v);
    return length === undefined || bytes.length === length;
  } catch {
    return false;
  }
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function usernameFromToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return undefined;
  const token = header.slice(7);
  for (const [t, user] of tokens) {
    if (safeEqual(t, token)) return user;
  }
  return undefined;
}

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const user = usernameFromToken(req);
  if (!user) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  res.locals.user = user;
  next();
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/register", (req, res) => {
  const { username, edPub, ik, spk, spkSig, opks } = req.body ?? {};
  if (typeof username !== "string" || !USERNAME_RE.test(username)) {
    res.status(400).json({ error: "invalid username" });
    return;
  }
  if (!isB64(edPub, 32) || !isB64(ik, 32) || !isB64(spk, 32) || !isB64(spkSig, 64)) {
    res.status(400).json({ error: "invalid key material" });
    return;
  }
  if (!verifyPreKey(unb64(edPub), unb64(spk), unb64(spkSig))) {
    res.status(400).json({ error: "invalid signed prekey" });
    return;
  }
  if (!Array.isArray(opks) || opks.length > MAX_OPKS) {
    res.status(400).json({ error: "invalid one-time prekeys" });
    return;
  }
  const seen = new Set<number>();
  const cleanOpks: { id: number; pub: string }[] = [];
  for (const opk of opks) {
    if (
      typeof opk !== "object" ||
      opk === null ||
      !Number.isInteger(opk.id) ||
      opk.id < 0 ||
      seen.has(opk.id) ||
      !isB64(opk.pub, 32)
    ) {
      res.status(400).json({ error: "invalid one-time prekey" });
      return;
    }
    seen.add(opk.id);
    cleanOpks.push({ id: opk.id, pub: opk.pub });
  }

  const user: StoredUser = {
    username,
    edPub,
    ik,
    spk,
    spkSig,
    opks: cleanOpks,
    createdAt: Date.now(),
  };
  if (!store.createUser(user)) {
    res.status(409).json({ error: "username taken" });
    return;
  }
  const token = b64(randomBytes(32));
  tokens.set(token, username);
  res.json({ token, username });
});

app.post("/api/challenge", (req, res) => {
  const { username } = req.body ?? {};
  if (typeof username !== "string" || !store.getUser(username)) {
    res.status(404).json({ error: "unknown user" });
    return;
  }
  const nonce = b64(randomBytes(32));
  challenges.set(username, { nonce, expires: Date.now() + 60_000 });
  res.json({ nonce });
});

app.post("/api/login", (req, res) => {
  const { username, signature } = req.body ?? {};
  if (typeof username !== "string" || !isB64(signature, 64)) {
    res.status(400).json({ error: "invalid login" });
    return;
  }
  const user = store.getUser(username);
  const challenge = challenges.get(username);
  if (!user || !challenge || challenge.expires < Date.now()) {
    res.status(401).json({ error: "challenge expired" });
    return;
  }
  challenges.delete(username);
  if (!verify(unb64(user.edPub), utf8(AUTH_PREFIX + challenge.nonce), unb64(signature))) {
    res.status(401).json({ error: "bad signature" });
    return;
  }
  const token = b64(randomBytes(32));
  tokens.set(token, username);
  res.json({ token, username });
});

app.get("/api/users", requireAuth, (_req, res) => {
  res.json({ users: store.listUsers() });
});

app.get("/api/identity/:username", requireAuth, (req, res) => {
  const name = req.params.username;
  if (!name) {
    res.status(400).json({ error: "missing username" });
    return;
  }
  const user = store.getUser(name);
  if (!user) {
    res.status(404).json({ error: "unknown user" });
    return;
  }
  res.json({ username: user.username, ik: user.ik, edPub: user.edPub });
});

app.get("/api/prekey/:username", requireAuth, (req, res) => {
  const name = req.params.username;
  if (!name) {
    res.status(400).json({ error: "missing username" });
    return;
  }
  const user = store.getUser(name);
  if (!user) {
    res.status(404).json({ error: "unknown user" });
    return;
  }
  const opk = store.takeOneTimePreKey(user.username);
  const bundle: Record<string, unknown> = {
    username: user.username,
    ik: user.ik,
    edPub: user.edPub,
    spk: user.spk,
    spkSig: user.spkSig,
  };
  if (opk) bundle.opk = opk;
  res.json(bundle);
});

function sendFrameToUser(username: string, frame: unknown): void {
  const set = sockets.get(username);
  if (!set) return;
  const data = JSON.stringify(frame);
  for (const ws of set) {
    if (ws.readyState === ws.OPEN) ws.send(data);
  }
}

function pushToUser(username: string, messages: Envelope[]): void {
  sendFrameToUser(username, { type: "messages", messages });
}

app.post("/api/send", requireAuth, (req, res) => {
  const from = res.locals.user as string;
  const { to, payload, cid } = req.body ?? {};
  if (typeof to !== "string" || !store.getUser(to)) {
    res.status(404).json({ error: "unknown recipient" });
    return;
  }
  if (typeof payload !== "string" || payload.length === 0 || payload.length > MAX_PAYLOAD) {
    res.status(400).json({ error: "invalid payload" });
    return;
  }
  if (cid !== undefined && (typeof cid !== "string" || cid.length > 100)) {
    res.status(400).json({ error: "invalid client id" });
    return;
  }
  const env: Envelope = {
    id: store.newId(),
    cid,
    from,
    to,
    payload,
    ts: Date.now(),
  };
  store.enqueue(env);
  pushToUser(to, [env]);
  res.json({ id: env.id });
});

app.post("/api/ack", requireAuth, (req, res) => {
  const user = res.locals.user as string;
  const { ids } = req.body ?? {};
  if (!Array.isArray(ids) || ids.length > 1000 || !ids.every((i) => typeof i === "string")) {
    res.status(400).json({ error: "invalid ids" });
    return;
  }
  const removed = store.ack(user, ids);
  const receipts = new Map<string, string[]>();
  for (const msg of removed) {
    if (!msg.cid) continue;
    const list = receipts.get(msg.from) ?? [];
    list.push(msg.cid);
    receipts.set(msg.from, list);
  }
  for (const [sender, cids] of receipts) {
    sendFrameToUser(sender, { type: "receipt", from: user, ids: cids, status: "delivered" });
  }
  res.json({ ok: true });
});

app.post(
  "/api/blob",
  requireAuth,
  express.raw({ type: "application/octet-stream", limit: "10mb" }),
  (req, res) => {
  const from = res.locals.user as string;
  const to = typeof req.query.to === "string" ? req.query.to : "";
  if (!to || !store.getUser(to)) {
    res.status(404).json({ error: "unknown recipient" });
    return;
  }
  const body = req.body;
  if (!Buffer.isBuffer(body) || body.length === 0 || body.length > 10 * 1024 * 1024) {
    res.status(400).json({ error: "invalid blob" });
    return;
  }
    const meta = store.saveBlob(from, to, body);
    res.json({ id: meta.id, size: meta.size });
  },
);

app.get("/api/blob/:id", requireAuth, (req, res) => {
  const user = res.locals.user as string;
  const id = req.params.id;
  if (!id) {
    res.status(400).json({ error: "missing blob id" });
    return;
  }
  const meta = store.getBlob(id);
  if (!meta || (meta.owner !== user && meta.recipient !== user)) {
    res.status(404).json({ error: "not found" });
    return;
  }
  const data = store.readBlob(id);
  if (!data) {
    res.status(404).json({ error: "not found" });
    return;
  }
  res.setHeader("content-type", "application/octet-stream");
  res.setHeader("cache-control", "private, max-age=0, no-store");
  res.send(Buffer.from(data));
});

const dist = resolve("dist");
if (existsSync(dist)) {
  app.use(express.static(dist));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api") || req.path === "/ws") return next();
    res.sendFile(resolve(dist, "index.html"));
  });
}

const server = createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  const url = new URL(req.url ?? "/ws", "http://localhost");
  const token = url.searchParams.get("token") ?? "";
  let username: string | undefined;
  for (const [t, user] of tokens) {
    if (safeEqual(t, token)) {
      username = user;
      break;
    }
  }
  if (!username) {
    ws.close(4001, "unauthorized");
    return;
  }

  let set = sockets.get(username);
  if (!set) {
    set = new Set();
    sockets.set(username, set);
  }
  set.add(ws);
  broadcastPresence();

  const pending = store.messagesFor(username);
  if (pending.length > 0) {
    ws.send(JSON.stringify({ type: "messages", messages: pending }));
  }

  let lastTyping = 0;
  ws.on("message", (raw) => {
    let frame: { type?: unknown; to?: unknown };
    try {
      frame = JSON.parse(String(raw));
    } catch {
      return;
    }
    if (frame?.type !== "typing" || typeof frame.to !== "string") return;
    if (!store.getUser(frame.to)) return;
    const now = Date.now();
    if (now - lastTyping < 800) return;
    lastTyping = now;
    sendFrameToUser(frame.to, { type: "typing", from: username });
  });

  ws.on("close", () => {
    set?.delete(ws);
    if (set && set.size === 0) sockets.delete(username!);
    broadcastPresence();
  });
});

server.listen(PORT, () => {
  console.log(`blacknoir relay listening on http://localhost:${PORT}`);
});
