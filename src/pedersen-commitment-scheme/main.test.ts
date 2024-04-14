import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { Point } from "../ecc/point.ts";
import { Secp256k1 } from "../ecc/curve.ts";
import { createCommitment, verifyCommitment } from "./main.ts";

describe("Pedersen Commitment Scheme", () => {
  it("should verify a valid commitment", async () => {
    const v = 42n;
    const { c, r } = await createCommitment(v);

    const isValid = await verifyCommitment(v, r, c);

    expect(isValid).toBe(true);
  });

  it("shouldn't verify an invalid commitment", async () => {
    const v = 42n;

    const curve = new Secp256k1();
    const c = new Point(curve, 1n, 1n);

    const { r } = await createCommitment(v);
    const isValid = await verifyCommitment(v, r, c);

    expect(isValid).toBe(false);
  });
});
