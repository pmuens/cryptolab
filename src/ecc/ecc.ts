import { PrivateKey } from "./types.ts";
import { Point } from "../shared/ecc/point.ts";
import { getRandomNumber } from "../shared/utils.ts";
import { Curve, Secp256k1 } from "../shared/ecc/curve.ts";

export class ECC {
  readonly sk: bigint;
  readonly pk: Point;
  readonly curve: Curve;

  constructor(sk?: PrivateKey, curve?: Curve) {
    this.curve = new Secp256k1();
    if (curve) {
      this.curve = curve;
    }

    const privateKey = sk || getRandomNumber(32, this.curve.n);

    const G = new Point(this.curve, this.curve.gx, this.curve.gy);
    const publicKey = G.scalarMul(privateKey);

    this.sk = privateKey;
    this.pk = publicKey;
  }
}
