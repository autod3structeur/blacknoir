import { unb64 } from "./bytes.ts";
import type { Identity } from "./keys.ts";
import { initInitiator, initResponder, type RatchetState } from "./ratchet.ts";
import {
  initiateX3DH,
  respondX3DH,
  type PreKeyBundle,
  type X3DHInit,
} from "./x3dh.ts";

export interface InitiatorSession {
  state: RatchetState;
  init: X3DHInit;
}

export async function startInitiator(
  identity: Identity,
  bundle: PreKeyBundle,
): Promise<InitiatorSession> {
  const { sk, ad, init } = await initiateX3DH(identity, bundle);
  const state = await initInitiator(sk, ad, unb64(bundle.spk));
  return { state, init };
}

export async function acceptResponder(
  identity: Identity,
  signedPreKeyPriv: Uint8Array,
  signedPreKeyPub: Uint8Array,
  oneTimePreKeyPriv: Uint8Array | undefined,
  init: X3DHInit,
  initiatorRatchetPub: Uint8Array,
): Promise<RatchetState> {
  const { sk, ad } = await respondX3DH(identity, signedPreKeyPriv, oneTimePreKeyPriv, init);
  return initResponder(sk, ad, signedPreKeyPriv, signedPreKeyPub, initiatorRatchetPub);
}
