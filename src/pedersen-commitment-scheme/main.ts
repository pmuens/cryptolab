import { Point } from "../ecc/point.ts";
import { Secp256k1 } from "../ecc/curve.ts";
import { getRandomNumber } from "../ecc/utils.ts";

export function createCommitment(v: bigint) {
  const r = getRandomNumber();
  const { G, H } = getCurveParams();

  const c1 = G.scalarMul(v);
  const c2 = H.scalarMul(r);
  const c = c1.add(c2);

  return {
    r,
    c,
  };
}

export function verifyCommitment(v: bigint, r: bigint, c: Point) {
  const { G, H } = getCurveParams();

  const c1 = G.scalarMul(v);
  const c2 = H.scalarMul(r);
  const cPrime = c1.add(c2);

  return c.x === cPrime.x && c.y === cPrime.y;
}

function getCurveParams() {
  const curve = new Secp256k1();
  const G = new Point(curve, curve.gx, curve.gy);

  // `x` is a secret that protocol participants shouldn't know.
  const x = 4711n;
  const H = G.scalarMul(x);

  return {
    G,
    H,
  };
}
