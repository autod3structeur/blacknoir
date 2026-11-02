import { describe, expect, it } from "vitest";
import {
  acceptResponder,
  b64,
  deserializeState,
  encodeHeader,
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  initiateX3DH,
  ratchetDecrypt,
  ratchetEncrypt,
  respondX3DH,
  serializeState,
  startInitiator,
  unb64,
  type Identity,
  type OneTimePreKey,
  type PreKeyBundle,
  type RatchetState,
  type SignedPreKey,
} from "../src/crypto/index.ts";

function makeUser(name: string) {
  const identity = generateIdentity();
  const spk = generateSignedPreKey(identity);
  const opks = generateOneTimePreKeys(1, 5);
  const bundle: PreKeyBundle = {
    username: name,
    ik: b64(identity.xPub),
    edPub: b64(identity.edPub),
    spk: b64(spk.pub),
    spkSig: b64(spk.sig),
    opk: { id: opks[0]!.id, pub: b64(opks[0]!.pub) },
  };
  return { identity, spk, opks, bundle };
}

function opkPriv(opks: OneTimePreKey[], id: number | undefined): Uint8Array | undefined {
  return opks.find((k) => k.id === id)?.priv;
}

async function establish(alice: Identity, bob: ReturnType<typeof makeUser>) {
  const started = await startInitiator(alice, bob.bundle);
  const first = await ratchetEncrypt(started.state, "first");
  const bobState = await acceptResponder(
    bob.identity,
    bob.spk.priv,
    bob.spk.pub,
    opkPriv(bob.opks, started.init.opkId),
    started.init,
    first.header.dh,
  );
  const opened = await ratchetDecrypt(bobState, first.header, first.ciphertext);
  expect(opened.plaintext).toBe("first");
  return { aliceState: first.state, bobState: opened.state, init: started.init };
}

describe("X3DH", () => {
  it("derives the same shared secret on both sides", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const a = await initiateX3DH(alice, bob.bundle);
    const b = await respondX3DH(
      bob.identity,
      bob.spk.priv,
      opkPriv(bob.opks, a.init.opkId),
      a.init,
    );
    expect(b64(a.sk)).toBe(b64(b.sk));
    expect(b64(a.ad)).toBe(b64(b.ad));
  });

  it("rejects a forged signed prekey", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const mallory = generateIdentity();
    const forged = {
      ...bob.bundle,
      spkSig: b64(generateSignedPreKey(mallory).sig),
    };
    await expect(initiateX3DH(alice, forged)).rejects.toThrow(/signature/);
  });
});

describe("double ratchet conversation", () => {
  it("exchanges messages in both directions", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState, bobState } = await establish(alice, bob);

    const reply = await ratchetEncrypt(bobState, "hi alice");
    const aliceOpened = await ratchetDecrypt(aliceState, reply.header, reply.ciphertext);
    expect(aliceOpened.plaintext).toBe("hi alice");

    const again = await ratchetEncrypt(aliceOpened.state, "how are you?");
    const bobOpened = await ratchetDecrypt(reply.state, again.header, again.ciphertext);
    expect(bobOpened.plaintext).toBe("how are you?");
  });

  it("handles messages arriving out of order", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState, bobState } = await establish(alice, bob);

    let s = aliceState;
    const msgs = [];
    for (const text of ["m0", "m1", "m2", "m3"]) {
      const r = await ratchetEncrypt(s, text);
      s = r.state;
      msgs.push(r);
    }

    const order = [3, 0, 2, 1];
    let bobS: RatchetState = bobState;
    for (const i of order) {
      const m = msgs[i]!;
      const r = await ratchetDecrypt(bobS, m.header, m.ciphertext);
      expect(r.plaintext).toBe(`m${i}`);
      bobS = r.state;
    }
  });

  it("keeps skipped keys across a DH ratchet", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState, bobState } = await establish(alice, bob);

    const m1 = await ratchetEncrypt(aliceState, "pending-1");
    const m2 = await ratchetEncrypt(m1.state, "pending-2");

    const first = await ratchetDecrypt(bobState, m1.header, m1.ciphertext);
    expect(first.plaintext).toBe("pending-1");

    const reply = await ratchetEncrypt(first.state, "bob replies, ratcheting");
    const aliceGot = await ratchetDecrypt(m2.state, reply.header, reply.ciphertext);
    expect(aliceGot.plaintext).toBe("bob replies, ratcheting");

    const recovered = await ratchetDecrypt(reply.state, m2.header, m2.ciphertext);
    expect(recovered.plaintext).toBe("pending-2");
  });

  it("rejects tampered ciphertext without advancing state", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState, bobState } = await establish(alice, bob);

    const msg = await ratchetEncrypt(aliceState, "secret");
    const tampered = msg.ciphertext.slice();
    tampered[0]! ^= 0xff;

    await expect(ratchetDecrypt(bobState, msg.header, tampered)).rejects.toThrow();
    const ok = await ratchetDecrypt(bobState, msg.header, msg.ciphertext);
    expect(ok.plaintext).toBe("secret");
  });

  it("rejects tampered headers", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState, bobState } = await establish(alice, bob);

    const msg = await ratchetEncrypt(aliceState, "secret");
    const bad = { ...msg.header, n: msg.header.n + 5 };
    await expect(ratchetDecrypt(bobState, bad, msg.ciphertext)).rejects.toThrow();
  });

  it("round-trips serialized session state", async () => {
    const alice = generateIdentity();
    const bob = makeUser("bob");
    const { aliceState } = await establish(alice, bob);

    const msg = await ratchetEncrypt(aliceState, "persist me");
    const restored = deserializeState(serializeState(msg.state));
    const next = await ratchetEncrypt(restored, "after restore");
    expect(next.header.n).toBe(msg.header.n + 1);
    expect(encodeHeader(next.header)).toHaveLength(40);
  });
});
