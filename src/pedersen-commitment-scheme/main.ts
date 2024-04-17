import { Point } from "../ecc/point.ts";
import { Secp256k1 } from "../ecc/curve.ts";
import { getRandomNumber } from "../ecc/utils.ts";

export class PedersenCommitment {
  H: Point;
  G: Point;

  // `x` is a secret that protocol participants shouldn't know.
  constructor(x: bigint = 4711n) {
    const curve = new Secp256k1();
    const G = new Point(curve, curve.gx, curve.gy);

    this.G = G;
    this.H = this.G.scalarMul(x);
  }

  create(v: bigint): { r: bigint; c: Point } {
    const r = getRandomNumber();

    const c1 = this.G.scalarMul(v);
    const c2 = this.H.scalarMul(r);
    const c = c1.add(c2);

    return {
      r,
      c,
    };
  }

  verify(v: bigint, r: bigint, c: Point): boolean {
    const c1 = this.G.scalarMul(v);
    const c2 = this.H.scalarMul(r);
    const cPrime = c1.add(c2);

    return c.x === cPrime.x && c.y === cPrime.y;
  }
}
