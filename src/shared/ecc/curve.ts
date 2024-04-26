import { assert } from "$std/assert/mod.ts";
import { crypto } from "$std/crypto/mod.ts";
import { DigestAlgorithm } from "$std/crypto/crypto.ts";

import { buf2hex } from "../utils.ts";

export class Curve {
  name: string;
  p: bigint;
  a: bigint;
  b: bigint;
  gx: bigint;
  gy: bigint;
  n: bigint;
  h: bigint;

  constructor(
    name: string,
    p: bigint,
    a: bigint,
    b: bigint,
    gx: bigint,
    gy: bigint,
    n: bigint,
    h: bigint,
  ) {
    this.name = name;
    this.p = p;
    this.a = a;
    this.b = b;
    this.gx = gx;
    this.gy = gy;
    this.n = n;
    this.h = h;
  }

  async bytes2Scalar(
    bytes: Uint8Array,
    algo: DigestAlgorithm = "SHA-512",
  ): Promise<bigint> {
    const digest = new Uint8Array(await crypto.subtle.digest(algo, bytes));
    const bytesNumber = BigInt(buf2hex(digest));

    // See: https://stackoverflow.com/q/54758130
    const nBits = BigInt(this.n.toString(2).length);
    const bytesNumberBits = BigInt(bytesNumber.toString(2).length);

    // Truncate hash to make it FIPS 180 compatible.
    const x = bytesNumber >> (bytesNumberBits - nBits);

    const xBits = BigInt(x.toString(2).length);
    assert(xBits <= nBits);

    return x;
  }
}

// See: https://en.bitcoin.it/wiki/Secp256k1
export class Secp256k1 extends Curve {
  constructor() {
    const name = "secp256k1";
    // Prime.
    const p = BigInt(
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
    // Curve coefficients.
    const a = 0n;
    const b = 7n;
    // Base point.
    const gx = BigInt(
      "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    const gy = BigInt(
      "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
    // Subgroup order.
    const n = BigInt(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    // Subgroup cofactor.
    const h = 1n;

    super(name, p, a, b, gx, gy, n, h);
  }
}
