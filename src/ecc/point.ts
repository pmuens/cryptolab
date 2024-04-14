import { assert } from "$std/assert/mod.ts";

import { Curve } from "./curve.ts";
import { inverseOf, mod, toBinary } from "./utils.ts";

export class Point {
  x: bigint;
  y: bigint;
  curve: Curve;

  constructor(curve: Curve, x: bigint, y: bigint) {
    this.x = x;
    this.y = y;
    this.curve = curve;
  }

  // Identity / Point at infinity.
  static infinity(curve: Curve): Point {
    return new Point(curve, 0n, 0n);
  }

  isOnCurve(): boolean {
    const x = this.x;
    const y = this.y;

    // Identity / Point at infinity is on curve.
    if (x === 0n && y === 0n) {
      return true;
    }

    const a = this.curve.a;
    const b = this.curve.b;
    const p = this.curve.p;
    const name = this.curve.name;

    // `y^2 = x^3 + ax + b`.
    const result = mod(y * y, p) === mod(x * x * x + a * x + b, p);

    if (!result) {
      throw new Error(`Point (${x}, ${y}) is not on curve ${name}...`);
    }

    return result;
  }

  // See: https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction#algebraic-addition
  // See: https://andrea.corbellini.name/2015/05/23/elliptic-curve-cryptography-finite-fields-and-discrete-logarithms#algebraic-sum
  double(): Point {
    assert(this.isOnCurve());

    const x1 = this.x;
    const y1 = this.y;
    const curve = this.curve;
    const a = curve.a;
    const p = curve.p;

    const m = mod((3n * x1 * x1 + a) * inverseOf(2n * y1, p), p);

    // Note: compared to `x3` in the `add` method we subtract `x1` from `x1`
    //  because we're dealing with the same point in the `double` case.
    const x3 = mod(m * m - x1 - x1, p);
    const y3 = mod(y1 + m * (x3 - x1), p);

    const point = new Point(curve, x3, mod(-y3, p));
    assert(point.isOnCurve());

    return point;
  }

  // See: https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction#algebraic-addition
  // See: https://andrea.corbellini.name/2015/05/23/elliptic-curve-cryptography-finite-fields-and-discrete-logarithms#algebraic-sum
  add(other: Point): Point {
    assert(this.isOnCurve());
    assert(other.isOnCurve());

    const x1 = this.x;
    const x2 = other.x;
    const y1 = this.y;
    const y2 = other.y;
    const curve = this.curve;
    const p = curve.p;

    // If `this` is the point `0`.
    if (x1 === 0n && y1 === 0n) {
      return other;
    }
    // If `other` is the point `0`.
    if (x2 === 0n && y2 === 0n) {
      return this;
    }

    // Point + (-Point) = 0.
    if (x1 === x2 && y1 === -y2) {
      return Point.infinity(curve);
    }

    // If both points are the same.
    if (x1 === x2 && y1 === y2) {
      return this.double();
    }

    const m = mod((y1 - y2) * inverseOf(x1 - x2, p), p);

    const x3 = mod(m * m - x1 - x2, p);
    const y3 = mod(y1 + m * (x3 - x1), p);

    const point = new Point(curve, x3, mod(-y3, p));
    assert(point.isOnCurve());

    return point;
  }

  scalarMul(k: bigint): Point {
    assert(this.isOnCurve());

    // Double-and-add.
    const bits = toBinary(k);

    let total = Point.infinity(this.curve);
    // deno-lint-ignore no-this-alias
    let addend: Point = this;

    for (const bit of bits) {
      if (bit === 1n) {
        total = total.add(addend);
      }
      addend = addend.double();
    }

    assert(total.isOnCurve());

    return total;
  }
}
