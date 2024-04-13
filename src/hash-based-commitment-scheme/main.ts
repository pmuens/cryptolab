import { crypto } from "$std/crypto/mod.ts";

export async function createCommitment(v: number) {
  const r = getRandomNumber(0, 1_000_000_000);
  const digest = await createDigest(v, r);
  const c = new Uint8Array(digest);

  return {
    r,
    c,
  };
}

export async function verifyCommitment(v: number, r: number, c: Uint8Array) {
  const digest = await createDigest(v, r);
  return isEqual(c, new Uint8Array(digest));
}

function createDigest(v: number, r: number) {
  const concat = [v, r];
  const data = Uint8Array.from(concat);
  return crypto.subtle.digest("SHA-256", data);
}

// See: https://stackoverflow.com/a/7228322
function getRandomNumber(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

// See: https://stackoverflow.com/q/76127214
function isEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) {
    return false;
  }

  return a.every((value, index) => value === b[index]);
}
