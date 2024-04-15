export function interpolate(evaluations: Evaluation[]): (x: number) => number {
  function f(x: number): number {
    let interpolationPolynomial = 0;

    for (let i = 0; i < evaluations.length; i++) {
      const xi = evaluations[i].x;
      const yi = evaluations[i].y;

      // Calculate basis polynomial.
      let basisPolynomial = 1;
      for (let j = 0; j < evaluations.length; j++) {
        if (j !== i) {
          const xj = evaluations[j].x;
          basisPolynomial *= (x - xj) / (xi - xj);
        }
      }

      // Rescale basis polynomial.
      basisPolynomial = yi * basisPolynomial;

      // Add basis polynomial to interpolation polynomial.
      interpolationPolynomial += basisPolynomial;
    }

    return interpolationPolynomial;
  }

  return f;
}

export type Evaluation = { x: number; y: number };
