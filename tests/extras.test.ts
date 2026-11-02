import { describe, expect, it } from "vitest";
import { b64, generateIdentity, safetyNumber } from "../src/crypto/index.ts";
import {
  createVault,
  openString,
  sealString,
  unlockVault,
} from "../src/crypto/vault.ts";

describe("safety numbers", () => {
  it("are identical for both participants regardless of argument order", () => {
    const a = generateIdentity();
    const b = generateIdentity();
    const ab = safetyNumber(a.xPub, b.xPub);
    const ba = safetyNumber(b.xPub, a.xPub);
    expect(ab).toBe(ba);
    expect(ab).toMatch(/^\d{10}( \d{10}){5}$/);
  });

  it("differ when either identity key differs", () => {
    const a = generateIdentity();
    const b = generateIdentity();
    const c = generateIdentity();
    expect(safetyNumber(a.xPub, b.xPub)).not.toBe(safetyNumber(a.xPub, c.xPub));
  });
});

describe("vault", () => {
  it("seals and opens values", async () => {
    const { key } = await createVault("correct horse battery staple");
    const blob = sealString(key, "top secret");
    expect(blob.c).not.toContain("top secret");
    expect(openString(key, blob)).toBe("top secret");
  });

  it("opens with the right passphrase and rejects the wrong one", async () => {
    const { meta, key } = await createVault("hunter2");
    expect(b64(await unlockVault("hunter2", meta))).toBe(b64(key));
    await expect(unlockVault("wrong", meta)).rejects.toThrow();
  });
});
