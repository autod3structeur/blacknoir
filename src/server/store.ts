import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
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
  from: string;
  to: string;
  payload: string;
  ts: number;
}

interface Persisted {
  users: Record<string, StoredUser>;
  messages: Envelope[];
}

const EMPTY: Persisted = { users: {}, messages: [] };

export class Store {
  private data: Persisted;
  private readonly file: string;

  constructor(file = resolve("data/store.json")) {
    this.file = file;
    try {
      this.data = JSON.parse(readFileSync(this.file, "utf8")) as Persisted;
      this.data.users ??= {};
      this.data.messages ??= [];
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

  ack(username: string, ids: string[]): void {
    const set = new Set(ids);
    const before = this.data.messages.length;
    this.data.messages = this.data.messages.filter(
      (m) => !(m.to === username && set.has(m.id)),
    );
    if (this.data.messages.length !== before) this.persist();
  }

  newId(): string {
    return randomUUID();
  }
}
