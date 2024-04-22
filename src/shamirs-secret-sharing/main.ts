import { Lagrange } from "../lagrange-interpolation/main.ts";
import { Evaluation, Polynomial } from "../shared/polynomial.ts";

export class SSS {
  t: number;
  n: number;
  modulus: bigint;
  lagrange: Lagrange;

  constructor(t: number, n: number, modulus: bigint) {
    this.t = t;
    this.n = n;
    this.modulus = modulus;
    this.lagrange = new Lagrange(modulus);
  }

  createEvaluations(s: bigint): Evaluation[] {
    const degree = this.t - 1;
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
