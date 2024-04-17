import { getRandomNumber, mod } from "../ecc/utils.ts";
import { Evaluation, Lagrange } from "../lagrange-interpolation/main.ts";

export class SSS {
  t: bigint;
  n: bigint;
  modulus: bigint;
  lagrange: Lagrange;

  constructor(t: bigint, n: bigint, modulus: bigint) {
    this.t = t;
    this.n = n;
    this.modulus = modulus;
    this.lagrange = new Lagrange(modulus);
  }

  createEvaluations(s: bigint): Evaluation[] {
    const degree = this.t - 1n;
    const polynomial = new Polynomial(degree, this.modulus);
    polynomial.coefficients[0] = s;

    const evaluations = [];
    for (let i = 1n; i <= this.n; i++) {
      const x = i;
      const y = polynomial.evaluate(i);

      evaluations.push({ x, y });
    }

    return evaluations;
  }

  recoverSecret(evaluations: Evaluation[]): bigint {
    const f = this.lagrange.interpolate(evaluations);
    return f(0n);
  }
}

class Polynomial {
  degree: bigint;
  modulus: bigint;
  // Ordered by increasing degree.
  coefficients: bigint[] = [];

  constructor(degree: bigint, modulus: bigint) {
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
