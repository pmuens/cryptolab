import { assert } from "$std/assert/mod.ts";
import { crypto } from "$std/crypto/mod.ts";

import { ECC } from "../shared/ecc/ecc.ts";
import { Point } from "../shared/ecc/point.ts";
import { PrivateKey, PublicKey } from "../shared/ecc/types.ts";
import { buf2hex, concat, getRandomNumber, mod } from "../shared/utils.ts";

export class SchnorrSignature extends ECC {
  G: Point;

  constructor(sk?: PrivateKey) {
    super(sk);
    this.G = new Point(this.curve, this.curve.gx, this.curve.gy);
  }

  async sign(message: Uint8Array): Promise<Signature> {
    const r = getRandomNumber(32, this.curve.n);
    const R = this.G.scalarMul(r);

    const c = await createChallenge(this.pk, R, message, this.curve.n);

    const e = mod(r + mod(c * this.sk, this.curve.n), this.curve.n);

    return {
      R,
      e,
    };
  }

  async verify(
    pk: PublicKey,
    message: Uint8Array,
    signature: Signature,
  ): Promise<boolean> {
    const c = await createChallenge(pk, signature.R, message, this.curve.n);

    const left = this.G.scalarMul(signature.e);
    const right = signature.R.add(pk.scalarMul(c));

    return left.x === right.x && left.y === right.y;
  }
}

async function createChallenge(
  PK: Point,
  R: Point,
  message: Uint8Array,
  n: bigint,
): Promise<bigint> {
  const data = concat(PK.x, PK.y, R.x, R.y, message);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", data));
  const msgNumber = BigInt(buf2hex(digest));

  // See: https://stackoverflow.com/q/54758130
  const nBits = BigInt(n.toString(2).length);
  const msgNumberBits = BigInt(msgNumber.toString(2).length);

  // Truncate hash to make it FIPS 180 compatible.
  const c = msgNumber >> (msgNumberBits - nBits);

  const cBits = BigInt(c.toString(2).length);
  assert(cBits <= nBits);

  return c;
}

type Signature = {
  R: Point;
  e: bigint;
};
