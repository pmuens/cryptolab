import { assert } from "$std/assert/mod.ts";

export function getRandomNumber(bytes = 32, modulus?: bigint): bigint {
  const array = new Uint8Array(bytes);

  crypto.getRandomValues(array);

  // See: https://stackoverflow.com/a/75259983
  const hexString = Array.from(array)
    .map((i) => i.toString(16).padStart(2, "0"))
    .join("");

  const number = BigInt(`0x${hexString}`);

  if (modulus) {
    return mod(number, modulus);
  }

  return number;
}

export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= 0 ? result : result + b;
}

// See: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
// See: https://brilliant.org/wiki/extended-euclidean-algorithm
// Returns [gcd, x, y] such that `(a * x) + (b * y) = gcd` (`gcd` -> `gcd(a, b)`).
export function egcd(a: bigint, b: bigint): bigint[] {
  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;

  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }

  const gcd = b;

  return [gcd, x, y];
}

// Returns multiplicative inverse of `number` modulo `modulus`.
// Returns integer `x` s.th. `(number * x) % modulus === 1`.
export function inverseOf(number: bigint, modulus: bigint): bigint {
  const a = mod(number, modulus);
  const [gcd, x, y] = egcd(a, modulus);

  if (gcd !== 1n) {
    // Either `number` is 0 or `modulus` is not prime.
    throw new Error(
      `${number} has no multiplicative inverse modulo ${modulus}...`,
    );
  }

  assert(mod(number * x, modulus) === 1n);
  assert(mod(number * x + modulus * y, modulus) === gcd);

  return mod(x, modulus);
}

// See: https://stackoverflow.com/a/56943145
export function int2BytesBe(int: bigint, padding = 32): Uint8Array {
  return int2BytesLe(int, padding).reverse();
}

// See: https://stackoverflow.com/a/56943145
export function int2BytesLe(int: bigint, padding = 32): Uint8Array {
  const result = new Uint8Array(padding);

  let i = 0;
  let bigint = int;
  while (bigint > 0n) {
    result[i] = Number(bigint % 256n);
    bigint = bigint / 256n;
    i += 1;
  }

  return result;
}

// LSB -> MSB.
export function* toBinary(number: bigint): Generator<bigint, void, unknown> {
  while (number) {
    yield number & 1n;
    number >>= 1n;
  }
}

// See: https://stackoverflow.com/a/40031979
export function buf2hex(buffer: Uint8Array, prefix = true): string {
  const result = [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

  if (prefix) {
    return `0x${result}`;
  }

  return result;
}
