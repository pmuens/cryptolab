import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { LCG } from "./main.ts";

describe("Linear Congruential Generator", () => {
  it("should generate random numbers", () => {
    const lcg = new LCG(42n);

    let rand;
    rand = lcg.rand();
    expect(rand).toBe(9039304369631583587n);

    rand = lcg.rand();
    expect(rand).toBe(8647191391818483560n);

    rand = lcg.rand();
    expect(rand).toBe(10334312345110439241n);

    rand = lcg.rand();
    expect(rand).toBe(459824130525332694n);
  });
});
