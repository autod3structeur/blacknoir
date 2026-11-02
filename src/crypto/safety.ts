import { sha256 } from "@noble/hashes/sha2.js";
import { concat, utf8 } from "./bytes.ts";

const INFO = utf8("blacknoir-safety-v1");

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

export function safetyNumber(a: Uint8Array, b: Uint8Array): string {
  const [first, second] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  const digest = sha256(concat(INFO, first, second));
  const groups: string[] = [];
  for (let g = 0; g < 6; g++) {
    let value = 0n;
    for (let i = 0; i < 5; i++) {
      value = (value << 8n) | BigInt(digest[g * 5 + i]!);
    }
    groups.push((value % 10000000000n).toString().padStart(10, "0"));
  }
  return groups.join(" ");
}

export function safetyNumberVerified(verified: string | null, current: string): boolean {
  return verified !== null && verified === current;
}
