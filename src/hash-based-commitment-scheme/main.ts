import { crypto } from "$std/crypto/mod.ts";

import { buf2hex, getRandomNumber, int2BytesBe } from "../ecc/utils.ts";

export async function createCommitment(
  v: bigint,
): Promise<{ r: bigint; c: Uint8Array }> {
  const r = getRandomNumber();
  const digest = await createDigest(v, r);
  const c = new Uint8Array(digest);

  return {
    r,
    c,
  };
}

export async function verifyCommitment(
  v: bigint,
  r: bigint,
  c: Uint8Array,
): Promise<boolean> {
  const digest = await createDigest(v, r);
  const cPrime = new Uint8Array(digest);

  return buf2hex(c) === buf2hex(cPrime);
}

function createDigest(v: bigint, r: bigint): Promise<ArrayBuffer> {
  const vBytes = int2BytesBe(v);
  const rBytes = int2BytesBe(r);

  const data = new Uint8Array(vBytes.length + rBytes.length);

  data.set(vBytes);
  data.set(rBytes, vBytes.length);

  return crypto.subtle.digest("SHA-256", data);
}
