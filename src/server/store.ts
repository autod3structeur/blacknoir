import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

export interface StoredUser {
  username: string;
  edPub: string;
  ik: string;
  spk: string;
  spkSig: string;
  opks: { id: number; pub: string }[];
  createdAt: number;
}

export interface Envelope {
  id: string;
  cid?: string;
  from: string;
  to: string;
  payload: string;
  ts: number;
}

export interface BlobMeta {
  id: string;
  owner: string;
  recipient: string;
  size: number;
  ts: number;
}

interface Persisted {
  users: Record<string, StoredUser>;
  messages: Envelope[];
  blobs: Record<string, BlobMeta>;
}

const EMPTY: Persisted = { users: {}, messages: [], blobs: {} };

export class Store {
  private data: Persisted;
  private readonly file: string;
  private readonly blobDir: string;

  constructor(file = resolve("data/store.json")) {
    this.file = file;
    this.blobDir = join(dirname(file), "blobs");
    try {
      this.data = JSON.parse(readFileSync(this.file, "utf8")) as Persisted;
      this.data.users ??= {};
      this.data.messages ??= [];
      this.data.blobs ??= {};
    } catch {
      this.data = structuredClone(EMPTY);
    }
  }

  private persist(): void {
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data));
    renameSync(tmp, this.file);
  }

  getUser(username: string): StoredUser | undefined {
    return this.data.users[username];
  }

  createUser(user: StoredUser): boolean {
    if (this.data.users[user.username]) return false;
    this.data.users[user.username] = user;
    this.persist();
    return true;
  }

  listUsers(): { username: string }[] {
    return Object.values(this.data.users).map((u) => ({ username: u.username }));
  }

  takeOneTimePreKey(username: string): { id: number; pub: string } | undefined {
    const user = this.data.users[username];
    if (!user) return undefined;
    const opk = user.opks.shift();
    if (opk) this.persist();
    return opk;
  }

  enqueue(env: Envelope): void {
    this.data.messages.push(env);
    this.persist();
  }

  messagesFor(username: string): Envelope[] {
    return this.data.messages.filter((m) => m.to === username);
  }

  ack(username: string, ids: string[]): Envelope[] {
    const set = new Set(ids);
    const removed = this.data.messages.filter((m) => m.to === username && set.has(m.id));
    if (removed.length === 0) return [];
    this.data.messages = this.data.messages.filter((m) => !set.has(m.id));
    this.persist();
    return removed;
  }

  saveBlob(owner: string, recipient: string, data: Uint8Array): BlobMeta {
    const id = randomUUID();
    mkdirSync(this.blobDir, { recursive: true });
    writeFileSync(join(this.blobDir, `${id}.bin`), data);
    const meta: BlobMeta = { id, owner, recipient, size: data.length, ts: Date.now() };
    this.data.blobs[id] = meta;
    this.persist();
    return meta;
  }

  getBlob(id: string): BlobMeta | undefined {
    return this.data.blobs[id];
  }

  readBlob(id: string): Uint8Array | undefined {
    try {
      return readFileSync(join(this.blobDir, `${id}.bin`));
    } catch {
      return undefined;
    }
  }

  newId(): string {
    return randomUUID();
  }
}
