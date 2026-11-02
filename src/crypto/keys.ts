import { ed25519, x25519 } from "@noble/curves/ed25519";
import { assertLength, concat, randomBytes, utf8 } from "./bytes.ts";

export interface Identity {
  edPriv: Uint8Array;
  edPub: Uint8Array;
  xPriv: Uint8Array;
  xPub: Uint8Array;
}

export interface SignedPreKey {
  priv: Uint8Array;
  pub: Uint8Array;
  sig: Uint8Array;
}

export interface OneTimePreKey {
  id: number;
  priv: Uint8Array;
  pub: Uint8Array;
}

export interface KeyPair {
  priv: Uint8Array;
  pub: Uint8Array;
}

export function generateX25519(): KeyPair {
  const priv = randomBytes(32);
  return { priv, pub: x25519.getPublicKey(priv) };
}

export function generateIdentity(): Identity {
  const edPriv = randomBytes(32);
  const xPriv = randomBytes(32);
  return {
    edPriv,
    edPub: ed25519.getPublicKey(edPriv),
    xPriv,
    xPub: x25519.getPublicKey(xPriv),
  };
}

export function signPreKey(identity: Identity, preKeyPub: Uint8Array): Uint8Array {
  return ed25519.sign(concat(utf8("blacknoir-SPK"), preKeyPub), identity.edPriv);
}

export function verifyPreKey(
  edPub: Uint8Array,
  preKeyPub: Uint8Array,
  sig: Uint8Array,
): boolean {
  try {
    return ed25519.verify(sig, concat(utf8("blacknoir-SPK"), preKeyPub), edPub);
  } catch {
    return false;
  }
}

export function generateSignedPreKey(identity: Identity): SignedPreKey {
  const kp = generateX25519();
  return { priv: kp.priv, pub: kp.pub, sig: signPreKey(identity, kp.pub) };
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  const out: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) {
    const kp = generateX25519();
    out.push({ id: startId + i, priv: kp.priv, pub: kp.pub });
  }
  return out;
}

export function sign(identity: Identity, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, identity.edPriv);
}

export function verify(edPub: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  try {
    assertLength(edPub, 32, "ed25519 public key");
    return ed25519.verify(sig, message, edPub);
  } catch {
    return false;
  }
}
