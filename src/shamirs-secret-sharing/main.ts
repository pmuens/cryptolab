import { getRandomNumber, mod } from "../ecc/utils.ts";
import { Evaluation, interpolate } from "../lagrange-interpolation/main.ts";

export class SSS {
  t: bigint;
  n: bigint;
  modulus: bigint;

  constructor(t: bigint, n: bigint, modulus: bigint) {
    this.t = t;
    this.n = n;
    this.modulus = modulus;
  }

  createEvaluations(s: bigint): Evaluation[] {
    const f = createPolynomial(s, this.t, this.modulus);

    const evaluations = [];
    for (let i = 1n; i <= this.n; i++) {
      const x = i;
      const y = f(i);

      evaluations.push({ x, y });
    }

    return evaluations;
  }

  recoverSecret(evaluations: Evaluation[]): bigint {
    const f = interpolate(evaluations, this.modulus);
    return f(0n);
  }
}

function createPolynomial(
  s: bigint,
  t: bigint,
  modulus: bigint,
): (x: bigint) => bigint {
  const degree = t - 1n;

  const coefficients = [];
  for (let i = 0; i < degree; i++) {
    coefficients.push(getRandomNumber(32, modulus));
  }

  const polynomial = [s, ...coefficients];

  function f(x: bigint): bigint {
    return polynomial.reduce(
      (accum, coef, idx) =>
        mod(accum + mod(coef * (x ** BigInt(idx)), modulus), modulus),
      0n,
    );
  }

  return f;
}
