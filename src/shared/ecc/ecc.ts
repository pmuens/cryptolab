import { Point } from "./point.ts";
import { PrivateKey } from "./types.ts";
import { getRandomNumber } from "../utils.ts";
import { Curve, Secp256k1 } from "./curve.ts";

export class ECC {
  sk: bigint;
  pk: Point;
  curve: Curve;

  constructor(sk?: PrivateKey, curve?: Curve) {
    this.curve = new Secp256k1();
    if (curve) {
      this.curve = curve;
    }

    const privateKey = sk || getRandomNumber(32, this.curve.n);
    const publicKey = this.curve.G.scalarMul(privateKey);

    this.sk = privateKey;
    this.pk = publicKey;
  }
}
