import { mod } from "../shared/utils.ts";
import { Point } from "../shared/ecc/point.ts";
import { Curve } from "../shared/ecc/curve.ts";
import { Polynomial } from "../shared/polynomial.ts";
import {
  DKG as DKGCore,
  Party as PartyCore,
} from "../distributed-key-generation/main.ts";

export class DKG extends DKGCore {
  parties: Party[];

  constructor(t: number, n: number, curve: Curve) {
    super(t, n, curve);

    const parties: Party[] = [];

    for (let i = 0; i < n; i++) {
      const id = i + 1;
      parties.push(new Party(id, t, curve));
    }

    // Connect parties with each other.
    for (const self of parties) {
      for (const other of parties) {
        if (self.id !== other.id) {
          self.connect(other);
        }
      }
    }

    this.parties = parties;
  }

  refresh(): void {
    for (const party of this.parties) {
      party.incrementEpoch();
      party.setPolynomial();
      party.setCommitments();
      party.broadcastCommitments();
    }
    for (const party of this.parties) {
      for (const key of Object.keys(party.partyData)) {
        const id = Number(key);
        const y = party.evaluatePolynomial(id);
        party.sendEvaluation(id, y);
      }
    }
    for (const party of this.parties) {
      party.verifyEvaluations();
      party.setSecretShare();
    }
  }
}

export class Party extends PartyCore {
  epoch = 0;

  setPolynomial(): void {
    this.polynomial = new Polynomial(this.t - 1, this.curve.n);

    if (this.epoch > 0) {
      // For a secret share refresh we need to set the constant term to `0` so
      //  that the original secret share is preserved when adding up the
      //  polynomials of all parties.
      this.polynomial.coefficients[0] = 0n;
    }
  }

  setCommitments(): void {
    if (!this.polynomial) {
      throw new Error(`Polynomial of party #${this.id} not set...`);
    }

    // If we're past the initial epoch, we shouldn't compute a commitment for
    //  the first coefficient as `0` doesn't have a (modular) multiplicative
    //  inverse.
    this.commitments = this.polynomial.coefficients.slice(
      this.epoch > 0 ? 1 : 0,
    ).map((coef) => this.curve.G.scalarMul(coef));
  }

  verifyEvaluations(): void {
    const results: boolean[] = [];

    for (const key of Object.keys(this.partyData)) {
      const id = Number(key);
      const { commitments, y } = this.partyData[id];
      if (!commitments || !y) {
        results.push(false);
      } else {
        const left = this.curve.G.scalarMul(y);
        const right = commitments.reduce(
          (accum, comm, idx) =>
            accum.add(
              comm.scalarMul(
                BigInt(this.id ** (idx + (this.epoch > 0 ? 1 : 0))),
              ),
            ),
          Point.infinity(this.curve),
        );

        results.push(left.x === right.x && left.y === right.y);
      }
    }

    const allValid = results.every((result) => result === true);
    if (!allValid) {
      throw new Error("Error validating evaluations...");
    }
  }

  setSecretShare(): void {
    if (!this.polynomial) {
      throw new Error(`Polynomial of party #${this.id} not set...`);
    }

    const ownY = this.polynomial.evaluate(BigInt(this.id));

    let result = ownY;
    for (const [key, value] of Object.entries(this.partyData)) {
      if (!value.y) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing the Y value from party #${id}...`,
        );
      }

      result = mod(result + value.y, this.curve.n);
    }

    // Refresh secret share if we're past the initial epoch.
    if (this.secretShare && this.epoch > 0) {
      result = mod(this.secretShare + result, this.curve.n);
    }

    this.secretShare = result;
  }

  incrementEpoch(): void {
    this.epoch += 1;
  }
}
