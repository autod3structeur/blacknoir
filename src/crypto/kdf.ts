import { ab, utf8 } from "./bytes.ts";

async function importHkdfKey(ikm: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", ab(ikm), "HKDF", false, ["deriveBits"]);
}

export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  const key = await importHkdfKey(ikm);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: ab(salt), info: ab(utf8(info)) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    ab(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, ab(data));
  return new Uint8Array(sig);
}
