import { mod } from "../shared/utils.ts";
import { Point } from "../shared/ecc/point.ts";
import { Evaluation, Polynomial } from "../shared/polynomial.ts";
import { PedersenCommitment } from "../pedersen-commitment-scheme/main.ts";

export class DKG {
  t: number;
  G: Point;
  modulus: bigint;
  parties: Party[] = [];
  pedersen: PedersenCommitment;

  constructor(t: number, n: number, G: Point, modulus: bigint) {
    this.t = t;
    this.G = G;
    this.modulus = modulus;
    this.pedersen = new PedersenCommitment(4711n);

    for (let i = 0; i < n; i++) {
      const id = i + 1;
      const party = new Party(id, this.t, this.modulus);

      this.parties.push(party);
    }
  }

  run(): Point[] {
    let results: Result[];

    results = this.calculateCoefficientCommitments();
    this.broadcastCoefficientCommitments(results);

    results = this.calculatePolynomialEvaluations();
    this.sendPolynomialEvaluations(results);

    this.verifyCoefficientCommitments();

    results = this.calculateMaskedCoefficients();
    this.broadcastMaskedCoefficients(results);

    this.verifyPolynomialEvaluations();

    this.calculateKeyShares();
    return this.calculatePublicKey();
  }

  // --- Coefficient Commitments ---
  private calculateCoefficientCommitments(): Result[] {
    const results: Result[] = [];

    for (const self of this.parties) {
      self.checkDataIntegrity(DataProperty.FPolynomialEvaluations);
      self.checkDataIntegrity(DataProperty.HPolynomialEvaluations);
      if (
        self.fPolynomial.coefficients.length !==
          self.hPolynomial.coefficients.length
      ) {
        throw new Error(
          'Coefficients of "f" and "h" polynomials don\'t have the same length...',
        );
      }

      for (const other of this.parties) {
        if (self.id !== other.id) {
          const commitments = self.fPolynomial.coefficients.map(
            (fCoef, index) => {
              const hCoef = self.hPolynomial.coefficients[index];
              const commitment = this.pedersen.create(fCoef, hCoef);
              return commitment.c;
            },
          );

          results.push({
            sender: self,
            receiver: other,
            data: commitments,
          });
        }
      }
    }

    return results;
  }

  private broadcastCoefficientCommitments(
    results: Result[],
  ): void {
    results.forEach((result) =>
      result.receiver.setCoefficientCommitments(
        result.sender.id,
        result.data as Point[],
      )
    );
  }

  private verifyCoefficientCommitments(): void {
    const allValid = this.parties.every((party) =>
      party.verifyCoefficientCommitments(this.pedersen.G, this.pedersen.H)
    );

    if (!allValid) {
      throw new Error(
        "Coefficient commitments evaluation failed...",
      );
    }
  }

  // --- Polynomial Evaluations ---
  private calculatePolynomialEvaluations(): Result[] {
    const results: Result[] = [];

    for (const self of this.parties) {
      for (const other of this.parties) {
        if (self.id !== other.id) {
          const fEvaluation = {
            type: PolynomialType.F,
            x: BigInt(other.id),
            y: self.f(BigInt(other.id)),
          };
          results.push({
            sender: self,
            receiver: other,
            data: fEvaluation,
          });

          const hEvaluation = {
            type: PolynomialType.H,
            x: BigInt(other.id),
            y: self.h(BigInt(other.id)),
          };
          results.push({
            sender: self,
            receiver: other,
            data: hEvaluation,
          });
        }
      }
    }

    return results;
  }

  private sendPolynomialEvaluations(
    results: Result[],
  ): void {
    results.forEach((result) => {
      const { type, x, y } = result.data as EvaluationResult;
      const evaluation = {
        x,
        y,
      };

      result.receiver.addEvaluation(
        type,
        result.sender.id,
        evaluation,
      );
    });
  }

  private verifyPolynomialEvaluations(): void {
    const allValid = this.parties.every((party) =>
      party.verifyPolynomialEvaluations(this.G)
    );

    if (!allValid) {
      throw new Error(
        "Polynomial evaluation failed...",
      );
    }
  }

  // --- Masked Coefficients ---
  private calculateMaskedCoefficients(): Result[] {
    const results: Result[] = [];

    for (const self of this.parties) {
      const maskedCoefficients = self.fPolynomial.coefficients.map((coef) =>
        this.G.scalarMul(coef)
      );

      for (const other of this.parties) {
        if (self.id !== other.id) {
          results.push({
            sender: self,
            receiver: other,
            data: maskedCoefficients,
          });
        }
      }
    }

    return results;
  }

  private broadcastMaskedCoefficients(
    results: Result[],
  ): void {
    results.forEach((result) =>
      result.receiver.setMaskedCoefficients(
        result.sender.id,
        result.data as Point[],
      )
    );
  }

  // --- Key Shares & Public Key ---
  private calculateKeyShares(): void {
    this.parties.forEach((party) => party.calculateKeyShare());
  }

  private calculatePublicKey(): Point[] {
    return this.parties.map((party) => party.calculatePublicKey(this.G));
  }
}

class Party {
  id: number;
  keyShare = 0n;
  modulus: bigint;
  fPolynomial: Polynomial;
  hPolynomial: Polynomial;
  f: (x: bigint) => bigint;
  h: (x: bigint) => bigint;
  partyData: Data;

  constructor(id: number, t: number, modulus: bigint) {
    this.id = id;
    this.modulus = modulus;
    this.fPolynomial = new Polynomial(t - 1, modulus);
    this.hPolynomial = new Polynomial(t - 1, modulus);
    this.f = this.fPolynomial.evaluate.bind(this.fPolynomial);
    this.h = this.hPolynomial.evaluate.bind(this.hPolynomial);
    this.partyData = {};
  }

  addEvaluation(
    type: PolynomialType,
    id: number,
    evaluation: Evaluation,
  ): void {
    this.ensurePartyData(id);

    if (type === PolynomialType.F) {
      this.partyData[id].fPolynomialEvaluations.push(evaluation);
    } else if (type === PolynomialType.H) {
      this.partyData[id].hPolynomialEvaluations.push(evaluation);
    }
  }

  setCoefficientCommitments(id: number, commitments: Point[]): void {
    this.ensurePartyData(id);
    this.partyData[id].coefficientCommitments = commitments;
  }

  setMaskedCoefficients(id: number, coefficients: Point[]): void {
    this.ensurePartyData(id);
    this.partyData[id].maskedCoefficients = coefficients;
  }

  verifyCoefficientCommitments(G: Point, H: Point): boolean {
    this.checkDataIntegrity(DataProperty.CoefficientCommitments);
    this.checkDataIntegrity(DataProperty.FPolynomialEvaluations);
    this.checkDataIntegrity(DataProperty.HPolynomialEvaluations);

    for (const [_, value] of Object.entries(this.partyData)) {
      const {
        fPolynomialEvaluations,
        hPolynomialEvaluations,
        coefficientCommitments,
      } = value;

      const left = coefficientCommitments.reduce((accum, comm, index) => {
        const result = comm.scalarMul(BigInt(this.id ** index));
        return accum.add(result);
      }, Point.infinity(G.curve));

      // Note: Using explicit typing here because we know that the
      //  accumulator is a `Point` (but the TypeScript compiler doesn't).
      const right = fPolynomialEvaluations.reduce<Point>(
        (accum, fEval, index) => {
          const hEval = hPolynomialEvaluations[index];
          const result = G.scalarMul(fEval.y).add(H.scalarMul(hEval.y));
          return accum.add(result);
        },
        Point.infinity(G.curve),
      );

      const isValid = left.x === right.x && left.y === right.y;

      if (!isValid) {
        return false;
      }
    }

    return true;
  }

  verifyPolynomialEvaluations(G: Point): boolean {
    this.checkDataIntegrity(DataProperty.FPolynomialEvaluations);
    this.checkDataIntegrity(DataProperty.MaskedCoefficients);

    for (const [_, value] of Object.entries(this.partyData)) {
      const { fPolynomialEvaluations, maskedCoefficients } = value;

      for (const evaluation of fPolynomialEvaluations) {
        const left = G.scalarMul(evaluation.y);
        const right = maskedCoefficients.reduce((accum, coef, index) => {
          const result = coef.scalarMul(BigInt(this.id ** index));
          return accum.add(result);
        }, Point.infinity(G.curve));

        const isValid = left.x === right.x && left.y === right.y;

        if (!isValid) {
          return false;
        }
      }
    }

    return true;
  }

  calculateKeyShare(): bigint {
    this.checkDataIntegrity(DataProperty.FPolynomialEvaluations);

    const evaluations: Evaluation[] = [];

    // Evaluate own polynomial and add it to the list of polynomial evaluations.
    evaluations.push(
      {
        x: BigInt(this.id),
        y: this.f(BigInt(this.id)),
      },
    );

    Object.entries(this.partyData).forEach(([_, value]) => {
      evaluations.push(...value.fPolynomialEvaluations);
    });

    this.keyShare = evaluations.reduce(
      (accum, evaluation) => mod(accum + evaluation.y, this.modulus),
      0n,
    );

    return this.keyShare;
  }

  calculatePublicKey(G: Point): Point {
    this.checkDataIntegrity(DataProperty.MaskedCoefficients);

    const ownZeroCoefficient = this.fPolynomial.coefficients[0];
    const ownMaskedZeroCoefficient = G.scalarMul(ownZeroCoefficient);

    const othersMaskedZeroCoefficients: Point[] = [];
    Object.entries(this.partyData).forEach(([_, value]) => {
      othersMaskedZeroCoefficients.push(value.maskedCoefficients[0]);
    });

    const others = othersMaskedZeroCoefficients.reduce(
      (accum, coef) => accum.add(coef),
      Point.infinity(G.curve),
    );

    return others.add(ownMaskedZeroCoefficient);
  }

  checkDataIntegrity(property: DataProperty): void {
    const { partyData } = this;

    const success = Object.entries(partyData).every(([key]) => {
      const firstEntryValue = Object.entries(partyData)[0][1];
      const currentEntryValue = partyData[Number(key)];

      return firstEntryValue[property].length ===
        currentEntryValue[property].length;
    });

    if (!success) {
      throw new Error(
        `Data inconsistency with property "${property}" (Party #${this.id})...`,
      );
    }
  }

  private ensurePartyData(id: number): void {
    if (!this.partyData[id]) {
      this.partyData[id] = {
        coefficientCommitments: [],
        fPolynomialEvaluations: [],
        hPolynomialEvaluations: [],
        maskedCoefficients: [],
      };
    }
  }
}

enum PolynomialType {
  F,
  H,
}

enum DataProperty {
  CoefficientCommitments = "coefficientCommitments",
  MaskedCoefficients = "maskedCoefficients",
  FPolynomialEvaluations = "fPolynomialEvaluations",
  HPolynomialEvaluations = "hPolynomialEvaluations",
}

type Data = {
  [partyId: number]: {
    coefficientCommitments: Point[];
    fPolynomialEvaluations: Evaluation[];
    hPolynomialEvaluations: Evaluation[];
    maskedCoefficients: Point[];
  };
};

type Result = {
  sender: Party;
  receiver: Party;
  data: EvaluationResult | Point[];
};

type EvaluationResult = Evaluation & { type: PolynomialType };
