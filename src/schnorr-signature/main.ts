import { ECC } from "../shared/ecc/ecc.ts";
import { Curve } from "../shared/ecc/curve.ts";
import { Point } from "../shared/ecc/point.ts";
import { PrivateKey, PublicKey } from "../shared/ecc/types.ts";
import { concat, getRandomNumber, mod } from "../shared/utils.ts";

export class SchnorrSignature extends ECC {
  G: Point;
  r: bigint;
  R: Point;

  constructor(sk?: PrivateKey, curve?: Curve) {
    super(sk, curve);
    this.G = new Point(this.curve, this.curve.gx, this.curve.gy);
    // Create a random nonce upon initialization.
    const { r, R } = this.createNonce();
    this.r = r;
    this.R = R;
  }

  async sign(message: Uint8Array): Promise<Signature> {
    const { r, R } = this.createNonce();
    const c = await this.createChallenge(this.pk, R, message);

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
    const c = await this.createChallenge(pk, signature.R, message);

    const left = this.G.scalarMul(signature.e);
    const right = signature.R.add(pk.scalarMul(c));

    return left.x === right.x && left.y === right.y;
  }

  async createChallenge(
    PK: Point,
    R: Point,
    message: Uint8Array,
  ): Promise<bigint> {
    const data = concat(PK.x, PK.y, R.x, R.y, message);
    return await this.curve.bytes2Scalar(data);
  }

  private createNonce(): { r: bigint; R: Point } {
    const r = getRandomNumber(32, this.curve.n);
    const R = this.G.scalarMul(r);

    this.r = r;
    this.R = R;

    return { r, R };
  }
}

export type Signature = {
  R: Point;
  e: bigint;
};
