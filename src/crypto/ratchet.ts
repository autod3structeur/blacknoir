import { x25519 } from "@noble/curves/ed25519";
import { aesGcmDecrypt, aesGcmEncrypt } from "./aead.ts";
import {
  assertLength,
  b64,
  bytesEqual,
  concat,
  fromUtf8,
  readU32,
  u32,
  unb64,
  utf8,
} from "./bytes.ts";
import { hkdf, hmacSha256 } from "./kdf.ts";
import { generateX25519 } from "./keys.ts";

const MAX_SKIP = 1000;
const RK_INFO = "blacknoir-RK-v1";
const MSG_INFO = "blacknoir-MSG-v1";
const ZERO_SALT = new Uint8Array(32);
const CHAIN_MSG = new Uint8Array([1]);
const CHAIN_NEXT = new Uint8Array([2]);

export interface RatchetHeader {
  dh: Uint8Array;
  pn: number;
  n: number;
}

export interface RatchetState {
  rootKey: Uint8Array;
  selfPriv: Uint8Array;
  selfPub: Uint8Array;
  remotePub: Uint8Array | null;
  sendChain: Uint8Array | null;
  recvChain: Uint8Array | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  ad: Uint8Array;
  skipped: Map<string, Uint8Array>;
}

export function encodeHeader(h: RatchetHeader): Uint8Array {
  assertLength(h.dh, 32, "ratchet public key");
  return concat(h.dh, u32(h.pn), u32(h.n));
}

export function decodeHeader(b: Uint8Array): RatchetHeader {
  if (b.length !== 40) throw new Error("invalid ratchet header");
  return { dh: b.slice(0, 32), pn: readU32(b, 32), n: readU32(b, 36) };
}

function skippedKey(dh: Uint8Array, n: number): string {
  return `${b64(dh)}:${n}`;
}

function cloneState(s: RatchetState): RatchetState {
  return {
    rootKey: s.rootKey,
    selfPriv: s.selfPriv,
    selfPub: s.selfPub,
    remotePub: s.remotePub,
    sendChain: s.sendChain,
    recvChain: s.recvChain,
    sendCount: s.sendCount,
    recvCount: s.recvCount,
    prevSendCount: s.prevSendCount,
    ad: s.ad,
    skipped: new Map(s.skipped),
  };
}

async function kdfRk(rootKey: Uint8Array, dhOut: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const okm = await hkdf(dhOut, rootKey, RK_INFO, 64);
  return [okm.slice(0, 32), okm.slice(32, 64)];
}

async function kdfCk(chainKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const msgKey = await hmacSha256(chainKey, CHAIN_MSG);
  const nextKey = await hmacSha256(chainKey, CHAIN_NEXT);
  return [msgKey, nextKey];
}

async function messageKeys(msgKey: Uint8Array): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
  const okm = await hkdf(msgKey, ZERO_SALT, MSG_INFO, 44);
  return { key: okm.slice(0, 32), nonce: okm.slice(32, 44) };
}

function headerAad(state: RatchetState, header: RatchetHeader): Uint8Array {
  return concat(state.ad, encodeHeader(header));
}

export async function initInitiator(
  sk: Uint8Array,
  ad: Uint8Array,
  remoteSignedPreKeyPub: Uint8Array,
): Promise<RatchetState> {
  const self = generateX25519();
  const dhOut = x25519.getSharedSecret(self.priv, remoteSignedPreKeyPub);
  const [rootKey, sendChain] = await kdfRk(sk, dhOut);
  return {
    rootKey,
    selfPriv: self.priv,
    selfPub: self.pub,
    remotePub: remoteSignedPreKeyPub,
    sendChain,
    recvChain: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    ad,
    skipped: new Map(),
  };
}

export async function initResponder(
  sk: Uint8Array,
  ad: Uint8Array,
  signedPreKeyPriv: Uint8Array,
  signedPreKeyPub: Uint8Array,
  initiatorRatchetPub: Uint8Array,
): Promise<RatchetState> {
  const dhOut = x25519.getSharedSecret(signedPreKeyPriv, initiatorRatchetPub);
  const [rootKey, recvChain] = await kdfRk(sk, dhOut);
  return {
    rootKey,
    selfPriv: signedPreKeyPriv,
    selfPub: signedPreKeyPub,
    remotePub: initiatorRatchetPub,
    sendChain: null,
    recvChain,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    ad,
    skipped: new Map(),
  };
}

async function ensureSendChain(s: RatchetState): Promise<void> {
  if (s.sendChain) return;
  if (!s.remotePub) throw new Error("cannot send without a remote ratchet key");
  const self = generateX25519();
  const dhOut = x25519.getSharedSecret(self.priv, s.remotePub);
  const [rootKey, sendChain] = await kdfRk(s.rootKey, dhOut);
  s.rootKey = rootKey;
  s.selfPriv = self.priv;
  s.selfPub = self.pub;
  s.sendChain = sendChain;
  s.sendCount = 0;
}

export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: string,
): Promise<{ state: RatchetState; header: RatchetHeader; ciphertext: Uint8Array }> {
  const s = cloneState(state);
  await ensureSendChain(s);
  if (!s.sendChain) throw new Error("send chain unavailable");

  const header: RatchetHeader = {
    dh: s.selfPub,
    pn: s.prevSendCount,
    n: s.sendCount,
  };
  const [msgKey, nextChain] = await kdfCk(s.sendChain);
  s.sendChain = nextChain;
  s.sendCount += 1;

  const { key, nonce } = await messageKeys(msgKey);
  const aad = headerAad(s, header);
  const ciphertext = await aesGcmEncrypt(key, nonce, utf8(plaintext), aad);
  return { state: s, header, ciphertext };
}

async function skipMessageKeys(s: RatchetState, until: number): Promise<void> {
  if (!s.remotePub) throw new Error("missing remote ratchet key");
  if (until - s.recvCount > MAX_SKIP) throw new Error("too many skipped messages");
  while (s.recvCount < until) {
    if (!s.recvChain) throw new Error("missing receiving chain");
    const [msgKey, nextChain] = await kdfCk(s.recvChain);
    s.recvChain = nextChain;
    s.skipped.set(skippedKey(s.remotePub, s.recvCount), msgKey);
    s.recvCount += 1;
  }
}

async function dhRatchet(s: RatchetState, remotePub: Uint8Array): Promise<void> {
  s.prevSendCount = s.sendCount;
  s.sendCount = 0;
  s.remotePub = remotePub;
  const dhOut = x25519.getSharedSecret(s.selfPriv, remotePub);
  const [rootKey, recvChain] = await kdfRk(s.rootKey, dhOut);
  s.rootKey = rootKey;
  s.recvChain = recvChain;
  s.recvCount = 0;

  const self = generateX25519();
  const dhOut2 = x25519.getSharedSecret(self.priv, remotePub);
  const [rootKey2, sendChain] = await kdfRk(s.rootKey, dhOut2);
  s.rootKey = rootKey2;
  s.selfPriv = self.priv;
  s.selfPub = self.pub;
  s.sendChain = sendChain;
}

async function decryptWith(
  s: RatchetState,
  msgKey: Uint8Array,
  header: RatchetHeader,
  ciphertext: Uint8Array,
): Promise<string> {
  const { key, nonce } = await messageKeys(msgKey);
  const pt = await aesGcmDecrypt(key, nonce, ciphertext, headerAad(s, header));
  return fromUtf8(pt);
}

export async function ratchetDecrypt(
  state: RatchetState,
  header: RatchetHeader,
  ciphertext: Uint8Array,
): Promise<{ state: RatchetState; plaintext: string }> {
  assertLength(header.dh, 32, "ratchet public key");
  const s = cloneState(state);

  const stored = s.skipped.get(skippedKey(header.dh, header.n));
  if (stored) {
    const plaintext = await decryptWith(s, stored, header, ciphertext);
    s.skipped.delete(skippedKey(header.dh, header.n));
    return { state: s, plaintext };
  }

  const sameChain = s.remotePub !== null && bytesEqual(header.dh, s.remotePub);
  if (!sameChain) {
    await skipMessageKeys(s, header.pn);
    await dhRatchet(s, header.dh);
  }

  if (!s.recvChain) throw new Error("missing receiving chain");
  await skipMessageKeys(s, header.n);
  if (!s.recvChain) throw new Error("missing receiving chain");
  const [msgKey, nextChain] = await kdfCk(s.recvChain);
  s.recvChain = nextChain;
  s.recvCount += 1;

  const plaintext = await decryptWith(s, msgKey, header, ciphertext);
  return { state: s, plaintext };
}

export interface SerializedRatchetState {
  rootKey: string;
  selfPriv: string;
  selfPub: string;
  remotePub: string | null;
  sendChain: string | null;
  recvChain: string | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  ad: string;
  skipped: [string, string][];
}

export function serializeState(s: RatchetState): SerializedRatchetState {
  return {
    rootKey: b64(s.rootKey),
    selfPriv: b64(s.selfPriv),
    selfPub: b64(s.selfPub),
    remotePub: s.remotePub ? b64(s.remotePub) : null,
    sendChain: s.sendChain ? b64(s.sendChain) : null,
    recvChain: s.recvChain ? b64(s.recvChain) : null,
    sendCount: s.sendCount,
    recvCount: s.recvCount,
    prevSendCount: s.prevSendCount,
    ad: b64(s.ad),
    skipped: [...s.skipped.entries()].map(([k, v]) => [k, b64(v)] as [string, string]),
  };
}

export function deserializeState(j: SerializedRatchetState): RatchetState {
  return {
    rootKey: unb64(j.rootKey),
    selfPriv: unb64(j.selfPriv),
    selfPub: unb64(j.selfPub),
    remotePub: j.remotePub ? unb64(j.remotePub) : null,
    sendChain: j.sendChain ? unb64(j.sendChain) : null,
    recvChain: j.recvChain ? unb64(j.recvChain) : null,
    sendCount: j.sendCount,
    recvCount: j.recvCount,
    prevSendCount: j.prevSendCount,
    ad: unb64(j.ad),
    skipped: new Map(j.skipped.map(([k, v]) => [k, unb64(v)])),
  };
}
