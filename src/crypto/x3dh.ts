import { x25519 } from "@noble/curves/ed25519";
import { assertLength, b64, concat, unb64 } from "./bytes.ts";
import { hkdf } from "./kdf.ts";
import { verifyPreKey, type Identity } from "./keys.ts";

const INFO = "blacknoir-X3DH-v1";
const ZERO_SALT = new Uint8Array(32);

export interface PreKeyBundle {
  username: string;
  ik: string;
  edPub: string;
  spk: string;
  spkSig: string;
  opk?: { id: number; pub: string };
}

export interface X3DHInit {
  ik: string;
  ek: string;
  opkId?: number;
}

export interface X3DHResult {
  sk: Uint8Array;
  ad: Uint8Array;
  init: X3DHInit;
}

function dh(priv: Uint8Array, pubB64: string): Uint8Array {
  const pub = unb64(pubB64);
  assertLength(pub, 32, "X25519 public key");
  return x25519.getSharedSecret(priv, pub);
}

function derive(skParts: Uint8Array[], ad: Uint8Array): Promise<Uint8Array> {
  return hkdf(concat(...skParts), ZERO_SALT, INFO, 32);
}

export async function initiateX3DH(
  identity: Identity,
  bundle: PreKeyBundle,
): Promise<X3DHResult> {
  const spk = unb64(bundle.spk);
  const edPub = unb64(bundle.edPub);
  if (!verifyPreKey(edPub, spk, unb64(bundle.spkSig))) {
    throw new Error("signed prekey signature is invalid");
  }

  const ek = x25519.utils.randomPrivateKey();
  const ekPub = x25519.getPublicKey(ek);

  const parts = [
    dh(identity.xPriv, bundle.spk),
    dh(ek, bundle.ik),
    dh(ek, bundle.spk),
    bundle.opk ? dh(ek, bundle.opk.pub) : new Uint8Array(32),
  ];

  const ad = concat(identity.xPub, unb64(bundle.ik));
  const sk = await derive(parts, ad);
  return {
    sk,
    ad,
    init: {
      ik: b64(identity.xPub),
      ek: b64(ekPub),
      opkId: bundle.opk?.id,
    },
  };
}

export async function respondX3DH(
  identity: Identity,
  spkPriv: Uint8Array,
  opkPriv: Uint8Array | undefined,
  init: X3DHInit,
): Promise<{ sk: Uint8Array; ad: Uint8Array }> {
  const ek = unb64(init.ek);
  assertLength(ek, 32, "ephemeral public key");
  const initiatorIk = unb64(init.ik);
  assertLength(initiatorIk, 32, "identity key");

  const parts = [
    x25519.getSharedSecret(spkPriv, initiatorIk),
    x25519.getSharedSecret(identity.xPriv, ek),
    x25519.getSharedSecret(spkPriv, ek),
    opkPriv ? x25519.getSharedSecret(opkPriv, ek) : new Uint8Array(32),
  ];

  const ad = concat(initiatorIk, identity.xPub);
  const sk = await derive(parts, ad);
  return { sk, ad };
}
