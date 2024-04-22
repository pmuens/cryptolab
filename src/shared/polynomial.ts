import { getRandomNumber, mod } from "./utils.ts";

export class Polynomial {
  degree: number;
  modulus: bigint;
  // Ordered by increasing degree.
  coefficients: bigint[] = [];

  constructor(degree: number, modulus: bigint) {
    this.degree = degree;
    this.modulus = modulus;

    for (let i = 0; i <= degree; i++) {
      this.coefficients.push(getRandomNumber(32, modulus));
    }
  }

  evaluate(x: bigint): bigint {
    return this.coefficients.reduce(
      (accum, coef, idx) =>
        mod(accum + mod(coef * (x ** BigInt(idx)), this.modulus), this.modulus),
      0n,
    );
  }
}

export type Evaluation = { x: bigint; y: bigint };
