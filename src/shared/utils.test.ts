import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { egcd, inverseOf, toBinary } from "./utils.ts";

describe("Utils", () => {
  it("toBinary", () => {
    const number = 151n;
    const result = [];

    for (const bit of toBinary(number)) {
      result.push(bit);
    }

    expect(result).toEqual([1n, 1n, 1n, 0n, 1n, 0n, 0n, 1n]);
  });

  it("egcd", () => {
    const a = 1432n;
    const b = 123211n;
    const [gcd, x, y] = egcd(a, b);

    expect(gcd).toBe(1n);
    expect(x).toBe(-22973n);
    expect(y).toBe(267n);
  });

  it("inverseOf", () => {
    const a = 4n;
    const b = 13n;
    const inverse = inverseOf(a, b);

    expect(inverse).toBe(10n);
  });
});
