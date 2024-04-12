import { assert } from "$std/assert/mod.ts";
import { crypto } from "$std/crypto/mod.ts";

import { ECC } from "./ecc.ts";
import { Point } from "./point.ts";
import { PublicKey, Signature } from "./types.ts";
import { buf2hex, getRandomNumber, inverseOf, mod } from "./utils.ts";

export class ECDSA extends ECC {
  async sign(message: Uint8Array): Promise<Signature> {
    const G = new Point(this.curve, this.curve.gx, this.curve.gy);
    const z = await hashMessage(message, this.curve.n);

    let r = 0n;
    let s = 0n;
    while (r === 0n || s === 0n) {
      const k = getRandomNumber(32, this.curve.n);
      const R = G.scalarMul(k);
      r = mod(R.x, this.curve.n);
      s = mod((z + r * this.sk) * inverseOf(k, this.curve.n), this.curve.n);
    }

    return {
      r,
      s,
    };
  }

  async verify(
    pk: PublicKey,
    message: Uint8Array,
    signature: Signature,
  ): Promise<boolean> {
    const G = new Point(this.curve, this.curve.gx, this.curve.gy);
    const z = await hashMessage(message, this.curve.n);

    const u = mod(z * inverseOf(signature.s, this.curve.n), this.curve.n);
    const v = mod(
      signature.r * inverseOf(signature.s, this.curve.n),
      this.curve.n,
    );

    const R = G.scalarMul(u).add(pk.scalarMul(v));

    return mod(signature.r, this.curve.n) === mod(R.x, this.curve.n);
  }
}

async function hashMessage(message: Uint8Array, n: bigint) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", message));
  const msgNumber = BigInt(buf2hex(digest));

  // See: https://stackoverflow.com/q/54758130
  const nBits = BigInt(n.toString(2).length);
  const msgNumberBits = BigInt(msgNumber.toString(2).length);

  // Truncate hash to make it FIPS 180 compatible.
  const z = msgNumber >> (msgNumberBits - nBits);

  const zBits = BigInt(z.toString(2).length);
  assert(zBits <= nBits);

  return z;
}
