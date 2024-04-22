import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { PedersenCommitment } from "./main.ts";
import { Point } from "../shared/ecc/point.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";

describe("Pedersen Commitment Scheme", () => {
  it("should verify a valid commitment", () => {
    const v = 42n;
    const commitment = new PedersenCommitment();

    const { c, r } = commitment.create(v);
    const isValid = commitment.verify(v, r, c);

    expect(isValid).toBe(true);
  });

  it("shouldn't verify an invalid commitment", () => {
    const v = 42n;
    const commitment = new PedersenCommitment();

    const curve = new Secp256k1();
    const c = new Point(curve, 1n, 1n);

    const { r } = commitment.create(v);
    const isValid = commitment.verify(v, r, c);

    expect(isValid).toBe(false);
  });
});
