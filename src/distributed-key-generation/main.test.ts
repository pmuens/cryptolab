import { expect } from "$std/expect/mod.ts";
import { beforeEach, describe, it } from "$std/testing/bdd.ts";

import { DKG } from "./main.ts";
import { mod } from "../shared/utils.ts";
import { Point } from "../shared/ecc/point.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";
import { Lagrange } from "../lagrange-interpolation/main.ts";

describe("Distributed Key Generation", () => {
  let curve: Secp256k1;
  let modulus: bigint;

  beforeEach(() => {
    curve = new Secp256k1();
    modulus = curve.n;
  });

  it("should derive a key pair and be able to recover the private key if the threshold is met", () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const G = new Point(curve, curve.gx, curve.gy);

    const dkg = new DKG(t, n, G, modulus);
    const pks = dkg.run();

    const [s, sPrime] = calculateSecrets(dkg, t);

    expect(sPrime).toBe(s);
    expect(allPksEqual(pks)).toBe(true);
  });

  it("should derive a key pair and be able to recover the private key if the threshold is exceeded", () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const G = new Point(curve, curve.gx, curve.gy);

    const dkg = new DKG(t, n, G, modulus);
    const pks = dkg.run();

    const [s, sPrime] = calculateSecrets(dkg, n);

    expect(sPrime).toBe(s);
    expect(allPksEqual(pks)).toBe(true);
  });

  it("should derive a key pair and not be able to recover the private key if the threshold is not met", () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const G = new Point(curve, curve.gx, curve.gy);

    const dkg = new DKG(t, n, G, modulus);
    const pks = dkg.run();

    const [s, sPrime] = calculateSecrets(dkg, t - 1);

    expect(sPrime).not.toBe(s);
    expect(allPksEqual(pks)).toBe(true);
  });
});

// See: https://stackoverflow.com/a/35568895
function allPksEqual(pks: Point[]): boolean {
  return pks.every((pk) => pk.x === pks[0].x && pk.y === pks[0].y);
}

function calculateSecrets(dkg: DKG, t: number): bigint[] {
  const lagrange = new Lagrange(dkg.modulus);

  const secret = dkg.parties.slice(0, t + 1).reduce(
    (accum, party) =>
      mod(accum + party.fPolynomial.coefficients[0], dkg.modulus),
    0n,
  );

  const evaluations = dkg.parties.map((party) => ({
    x: BigInt(party.id),
    y: party.keyShare,
  }));
  const f = lagrange.interpolate(evaluations);
  const secretPrime = f(0n);

  return [secret, secretPrime];
}
