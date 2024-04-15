import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { interpolate } from "./main.ts";

describe("Lagrange Interpolation", () => {
  it("should generate an interpolation polynomial of degree 0", () => {
    const evaluations = [{ x: 1, y: 2 }];

    const f = interpolate(evaluations);

    const e1 = evaluations[0];

    expect(f(e1.x)).toBe(e1.y);
  });

  it("should generate an interpolation polynomial of degree 1", () => {
    const evaluations = [{ x: 1, y: 2 }, { x: 3, y: 4 }];

    const f = interpolate(evaluations);

    const e1 = evaluations[0];
    const e2 = evaluations[1];

    expect(f(0)).toBe(1);
    expect(f(e1.x)).toBe(e1.y);
    expect(f(e2.x)).toBe(e2.y);
  });

  it("should generate an interpolation polynomial of degree 2", () => {
    const evaluations = [{ x: 1, y: 2 }, { x: 2, y: 3 }, { x: 3, y: 6 }];

    const f = interpolate(evaluations);

    const e1 = evaluations[0];
    const e2 = evaluations[1];
    const e3 = evaluations[2];

    expect(f(0)).toBe(3);
    expect(f(e1.x)).toBe(e1.y);
    expect(f(e2.x)).toBe(e2.y);
    expect(f(e3.x)).toBe(e3.y);
  });
});
