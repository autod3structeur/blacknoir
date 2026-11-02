import { ab, assertLength } from "./bytes.ts";

const TAG_BITS = 128;

export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  assertLength(key, 32, "AES-256 key");
  assertLength(nonce, 12, "GCM nonce");
  const k = await crypto.subtle.importKey("raw", ab(key), "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ab(nonce), additionalData: ab(aad), tagLength: TAG_BITS },
    k,
    ab(plaintext),
  );
  return new Uint8Array(ct);
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  assertLength(key, 32, "AES-256 key");
  assertLength(nonce, 12, "GCM nonce");
  const k = await crypto.subtle.importKey("raw", ab(key), "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ab(nonce), additionalData: ab(aad), tagLength: TAG_BITS },
    k,
    ab(ciphertext),
  );
  return new Uint8Array(pt);
}
