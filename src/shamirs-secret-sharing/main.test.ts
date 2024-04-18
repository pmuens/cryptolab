import { expect } from "$std/expect/mod.ts";
import { beforeEach, describe, it } from "$std/testing/bdd.ts";

import { SSS } from "./main.ts";
import { Secp256k1 } from "../ecc/curve.ts";

describe("Schamir's Secret Sharing", () => {
  let modulus: bigint;

  beforeEach(() => {
    const curve = new Secp256k1();
    modulus = curve.n;
  });

  it("should recover the correct secret if the threshold is met", () => {
    const s = 42n;

    // 3 / 5 Scheme.
    const t = 3;
    const n = 5;

    const shamir = new SSS(t, n, modulus);

    const evaluations = shamir.createEvaluations(s);

    // Using three evaluations should meet the threshold (3 / 5).
    const sPrime = shamir.recoverSecret(evaluations.slice(0, t));

    expect(sPrime).toBe(s);
  });

  it("should recover the correct secret if the threshold is exceeded", () => {
    const s = 42n;

    // 3 / 5 Scheme.
    const t = 3;
    const n = 5;

    const shamir = new SSS(t, n, modulus);

    const evaluations = shamir.createEvaluations(s);

    // Using all evaluations should meet the threshold (3 / 5).
    const sPrime = shamir.recoverSecret(evaluations.slice(0, n));

    expect(sPrime).toBe(s);
  });

  it("should not recover the correct secret if the threshold is not met", () => {
    const s = 42n;

    // 4 / 6 Scheme.
    const t = 4;
    const n = 6;

    const shamir = new SSS(t, n, modulus);

    const evaluations = shamir.createEvaluations(s);

    // Using three evaluations should not meet the threshold (4 / 6).
    const sPrime = shamir.recoverSecret(evaluations.slice(0, t - 1));

    expect(sPrime).not.toBe(s);
  });
});
