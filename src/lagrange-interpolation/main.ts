import { inverseOf, mod } from "../ecc/utils.ts";

export function interpolate(
  evaluations: Evaluation[],
  modulus: bigint,
): (x: bigint) => bigint {
  function f(x: bigint): bigint {
    let interpolationPolynomial = 0n;

    for (let i = 0; i < evaluations.length; i++) {
      const xi = evaluations[i].x;
      const yi = evaluations[i].y;

      // Calculate basis polynomial.
      let basisPolynomial = 1n;
      for (let j = 0; j < evaluations.length; j++) {
        if (j !== i) {
          const xj = evaluations[j].x;
          const numerator = mod(x - xj, modulus);
          const denominator = mod(xi - xj, modulus);
          const fraction = mod(
            numerator * inverseOf(denominator, modulus),
            modulus,
          );
          basisPolynomial = mod(basisPolynomial * fraction, modulus);
        }
      }

      // Rescale basis polynomial.
      basisPolynomial = mod(yi * basisPolynomial, modulus);

      // Add basis polynomial to interpolation polynomial.
      interpolationPolynomial = mod(
        interpolationPolynomial + basisPolynomial,
        modulus,
      );
    }

    return interpolationPolynomial;
  }

  return f;
}

export type Evaluation = { x: bigint; y: bigint };
