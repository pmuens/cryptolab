import { expect } from "$std/expect/mod.ts";
import { beforeEach, describe, it } from "$std/testing/bdd.ts";

import { Lagrange } from "./main.ts";
import { Secp256k1 } from "../ecc/curve.ts";

describe("Lagrange Interpolation", () => {
  let modulus: bigint;

  beforeEach(() => {
    const curve = new Secp256k1();
    modulus = curve.n;
  });

  it("should generate an interpolation polynomial of degree 0", () => {
    const evaluations = [{ x: 1n, y: 2n }];

    const lagrange = new Lagrange(modulus);
    const f = lagrange.interpolate(evaluations);

    const e1 = evaluations[0];

    expect(f(e1.x)).toBe(e1.y);
  });

  it("should generate an interpolation polynomial of degree 1", () => {
    const evaluations = [{ x: 1n, y: 2n }, { x: 3n, y: 4n }];

    const lagrange = new Lagrange(modulus);
    const f = lagrange.interpolate(evaluations);

    const e1 = evaluations[0];
    const e2 = evaluations[1];

    expect(f(0n)).toBe(1n);
    expect(f(e1.x)).toBe(e1.y);
    expect(f(e2.x)).toBe(e2.y);
  });

  it("should generate an interpolation polynomial of degree 2", () => {
    const evaluations = [{ x: 1n, y: 2n }, { x: 2n, y: 3n }, { x: 3n, y: 6n }];

    const lagrange = new Lagrange(modulus);
    const f = lagrange.interpolate(evaluations);

    const e1 = evaluations[0];
    const e2 = evaluations[1];
    const e3 = evaluations[2];

    expect(f(0n)).toBe(3n);
    expect(f(e1.x)).toBe(e1.y);
    expect(f(e2.x)).toBe(e2.y);
    expect(f(e3.x)).toBe(e3.y);
  });
});
