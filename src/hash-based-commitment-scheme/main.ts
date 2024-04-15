import { crypto } from "$std/crypto/mod.ts";

import { buf2hex } from "../ecc/utils.ts";

export async function createCommitment(
  v: number,
): Promise<{ r: number; c: Uint8Array }> {
  const r = getRandomNumber(0, 1_000_000_000);
  const digest = await createDigest(v, r);
  const c = new Uint8Array(digest);

  return {
    r,
    c,
  };
}

export async function verifyCommitment(
  v: number,
  r: number,
  c: Uint8Array,
): Promise<boolean> {
  const digest = await createDigest(v, r);
  const cPrime = new Uint8Array(digest);

  return buf2hex(c) === buf2hex(cPrime);
}

function createDigest(v: number, r: number): Promise<ArrayBuffer> {
  const concat = [v, r];
  const data = Uint8Array.from(concat);
  return crypto.subtle.digest("SHA-256", data);
}

// See: https://stackoverflow.com/a/7228322
export function getRandomNumber(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1) + min);
}
