import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { createEvaluations, recoverSecret } from "./main.ts";

describe("Schamir's Secret Sharing", () => {
  it("should recover the correct secret if the threshold is met", () => {
    const s = 42;

    // 3 / 5 Scheme.
    const t = 3;
    const n = 5;

    const evaluations = createEvaluations(s, t, n);

    // Using three evaluations should meet the threshold (3 / 5).
    const sPrime = recoverSecret(evaluations.slice(0, 3));

    expect(sPrime).toBe(s);
  });

  it("should recover the correct secret if the threshold is exceeded", () => {
    const s = 42;

    // 3 / 5 Scheme.
    const t = 3;
    const n = 5;

    const evaluations = createEvaluations(s, t, n);

    // Using all evaluations should meet the threshold (3 / 5).
    const sPrime = recoverSecret(evaluations);

    expect(sPrime).toBe(s);
  });

  it("should not recover the correct secret if the threshold is not met", () => {
    const s = 42;

    // 4 / 6 Scheme.
    const t = 4;
    const n = 6;

    const evaluations = createEvaluations(s, t, n);

    // Using three evaluations should not meet the threshold (4 / 6).
    const sPrime = recoverSecret(evaluations.slice(0, 3));

    expect(sPrime).not.toBe(s);
  });
});
