import { ECC } from "../shared/ecc/ecc.ts";
import { PublicKey } from "../shared/ecc/types.ts";
import { getRandomNumber, inverseOf, mod } from "../shared/utils.ts";

export class ECDSA extends ECC {
  async sign(message: Uint8Array): Promise<Signature> {
    const z = await this.curve.bytes2Scalar(message);

    let r = 0n;
    let s = 0n;
    while (r === 0n || s === 0n) {
      const k = getRandomNumber(32, this.curve.n);
      const R = this.curve.G.scalarMul(k);
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
    const z = await this.curve.bytes2Scalar(message);

    const u = mod(z * inverseOf(signature.s, this.curve.n), this.curve.n);
    const v = mod(
      signature.r * inverseOf(signature.s, this.curve.n),
      this.curve.n,
    );

    const R = this.curve.G.scalarMul(u).add(pk.scalarMul(v));

    return mod(signature.r, this.curve.n) === mod(R.x, this.curve.n);
  }
}

type Signature = {
  r: bigint;
  s: bigint;
};
