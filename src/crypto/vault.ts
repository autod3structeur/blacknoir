import { gcm } from "@noble/ciphers/aes.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { b64, fromUtf8, randomBytes, unb64, utf8 } from "./bytes.ts";

const SALT_BYTES = 16;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const ARGON = { t: 2, m: 19456, p: 1 } as const;
const CHECK_TEXT = "blacknoir-vault-check";

export interface VaultBlob {
  v: 1;
  n: string;
  c: string;
}

export interface VaultMeta {
  v: 1;
  salt: string;
  check: VaultBlob;
}

export function isVaultBlob(value: unknown): value is VaultBlob {
  if (!value || typeof value !== "object") return false;
  const b = value as Record<string, unknown>;
  return b.v === 1 && typeof b.n === "string" && typeof b.c === "string";
}

export function newVaultSalt(): string {
  return b64(randomBytes(SALT_BYTES));
}

export async function deriveVaultKey(passphrase: string, saltB64: string): Promise<Uint8Array> {
  const salt = unb64(saltB64);
  return argon2id(utf8(passphrase), salt, { ...ARGON, dkLen: KEY_BYTES });
}

export function sealString(key: Uint8Array, plaintext: string): VaultBlob {
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = gcm(key, nonce).encrypt(utf8(plaintext));
  return { v: 1, n: b64(nonce), c: b64(ciphertext) };
}

export function openString(key: Uint8Array, blob: VaultBlob): string {
  const plaintext = gcm(key, unb64(blob.n)).decrypt(unb64(blob.c));
  return fromUtf8(plaintext);
}

export async function createVault(passphrase: string): Promise<{ key: Uint8Array; meta: VaultMeta }> {
  const salt = newVaultSalt();
  const key = await deriveVaultKey(passphrase, salt);
  return {
    key,
    meta: { v: 1, salt, check: sealString(key, CHECK_TEXT) },
  };
}

export async function unlockVault(passphrase: string, meta: VaultMeta): Promise<Uint8Array> {
  const key = await deriveVaultKey(passphrase, meta.salt);
  const check = openString(key, meta.check);
  if (check !== CHECK_TEXT) throw new Error("invalid passphrase");
  return key;
}
