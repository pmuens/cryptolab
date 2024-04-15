import { getRandomNumber } from "../hash-based-commitment-scheme/main.ts";
import { Evaluation, interpolate } from "../lagrange-interpolation/main.ts";

export function createEvaluations(
  s: number,
  t: number,
  n: number,
): Evaluation[] {
  const f = createPolynomial(s, t);

  const evaluations = [];
  for (let i = 1; i <= n; i++) {
    const x = i;
    const y = f(i);

    evaluations.push({ x, y });
  }

  return evaluations;
}

function createPolynomial(s: number, t: number): (x: number) => number {
  const degree = t - 1;

  const coefficients = [];
  for (let i = 0; i < degree; i++) {
    coefficients.push(getRandomNumber(1, 1_000_000_000));
  }

  const polynomial = [s, ...coefficients];

  function f(x: number): number {
    return polynomial.reduce(
      (accum, coef, idx) => accum += coef * (x ** idx),
      0,
    );
  }

  return f;
}

export function recoverSecret(evaluations: Evaluation[]): number {
  const f = interpolate(evaluations);
  return f(0);
}
