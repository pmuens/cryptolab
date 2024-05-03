import { assert } from "$std/assert/assert.ts";

import { Point } from "../shared/ecc/point.ts";
import { Curve } from "../shared/ecc/curve.ts";
import { mod, pk2Bytes } from "../shared/utils.ts";
import { Polynomial } from "../shared/polynomial.ts";
import { SchnorrSignature, Signature } from "../schnorr-signature/main.ts";

// The following is an implementation of the Distributed Key Generation algorithm described in the
//  [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852) paper.
// The implementation extends the algorithm in the paper by also offering a way to refresh secret
//  shares.
export class DKG {
  t: number;
  parties: Party[] = [];

  constructor(t: number, n: number, curve: Curve) {
    const parties: Party[] = [];

    for (let i = 0; i < n; i++) {
      const id = i + 1;
      parties.push(new Party(id, t, curve));
    }

    this.t = t;
    this.parties = parties;
  }

  async run(): Promise<Point> {
    this.establishConnections();

    // Round #1.
    this.generateCommitments();
    await this.generateKosk();
    this.broadcastKosk();
    this.broadcastCommitments();
    await this.verifyKosks();

    // Round #2.
    this.sendEvaluations();
    this.verifyEvaluations();
    this.calculateSecretShare();
    return this.calculatePublicKey();
  }

  refresh(): void {
    this.updatePolynomial();
    this.generateCommitments();
    this.broadcastCommitments();

    this.sendEvaluations();
    this.verifyEvaluations();

    this.calculateSecretShare();
  }

  private establishConnections(): void {
    for (const self of this.parties) {
      for (const other of this.parties) {
        if (self.id !== other.id) {
          self.connect(other);
        }
      }
    }
  }

  private updatePolynomial(): void {
    for (const party of this.parties) {
      party.updatePolynomial();
    }
  }

  private async generateKosk(): Promise<void> {
    const promises: Promise<Signature>[] = [];

    for (const party of this.parties) {
      promises.push(party.generateKosk());
    }

    await Promise.all(promises);
  }

  private broadcastKosk(): void {
    for (const party of this.parties) {
      party.broadcastKosk();
    }
  }

  private generateCommitments(): void {
    for (const party of this.parties) {
      party.generateCommitments();
    }
  }

  private broadcastCommitments(): void {
    for (const party of this.parties) {
      party.broadcastCommitments();
    }
  }

  private async verifyKosks(): Promise<void> {
    const promises: Promise<boolean>[] = [];
    for (const party of this.parties) {
      promises.push(party.verifyKosks());
    }

    const results = await Promise.all(promises);
    const allValid = results.every((result) => result === true);

    if (!allValid) {
      throw new Error("Error validating KOSKs...");
    }
  }

  private sendEvaluations(): void {
    for (const party of this.parties) {
      party.sendEvaluations();
    }
  }

  private verifyEvaluations(): void {
    const results: boolean[] = [];

    for (const party of this.parties) {
      results.push(party.verifyEvaluations());
    }

    const allValid = results.every((result) => result === true);

    if (!allValid) {
      throw new Error("Error validating evaluations...");
    }
  }

  private calculateSecretShare(): void {
    for (const party of this.parties) {
      party.calculateSecretShare();
    }
  }

  private calculatePublicKey(): Point {
    const pks: Point[] = [];

    for (const party of this.parties) {
      pks.push(party.calculatePublicKey());
    }

    // See: https://stackoverflow.com/a/35568895
    const allEqual = pks.every((pk) => pk.x === pks[0].x && pk.y === pks[0].y);

    if (!allEqual) {
      throw new Error("Public Keys aren't all equal...");
    }

    return pks[0];
  }
}

export class Party implements P2P {
  id: Id;
  t: number;
  epoch = 0;
  curve: Curve;
  polynomial: Polynomial;
  kosk?: Signature;
  commitments?: Point[];
  secretShare?: bigint;
  publicKey?: Point;
  parties: PartyData = {};

  constructor(
    id: Id,
    t: number,
    curve: Curve,
  ) {
    if (id <= 0) {
      throw new Error(`The party's id needs to be >= 1 but is ${id}...`);
    }

    this.id = id;
    this.t = t;
    this.curve = curve;

    this.polynomial = this.generatePolynomial();
  }

  connect(party: Party): void {
    const id = party.id;
    const send = party.send.bind(party);
    const receive = party.receive.bind(party);

    this.parties[id] = {
      send,
      receive,
    };
  }

  broadcast(payload: Payload): void {
    for (const key of Object.keys(this.parties)) {
      const id = Number(key);
      this.send(id, payload);
    }
  }

  send(to: Id, payload: Payload): void {
    // deno-lint-ignore no-non-null-assertion
    this.parties[to].receive!(this.id, payload);
  }

  receive(from: Id, payload: Payload): void {
    switch (payload.type) {
      case Message.Kosk:
        this.parties[from].kosk = payload.data.kosk;
        break;
      case Message.Commitments:
        this.parties[from].commitments = payload.data.commitments;
        break;
      case Message.Evaluation:
        this.parties[from].y = payload.data.y;
        break;
    }
  }

  updatePolynomial(): Polynomial {
    this.epoch += 1;
    this.polynomial = this.generatePolynomial();
    return this.polynomial;
  }

  async generateKosk(): Promise<Signature> {
    if (!this.commitments) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    const sk = this.polynomial.coefficients[0];
    const pk = this.commitments[0];
    const schnorr = new SchnorrSignature(sk, this.curve);

    assert(schnorr.curve.name === this.curve.name);
    assert(schnorr.pk.x === pk.x && schnorr.pk.y === pk.y);

    this.kosk = await schnorr.sign(pk2Bytes(pk));

    return this.kosk;
  }

  broadcastKosk(): void {
    if (!this.kosk) {
      throw new Error(`KOSK of party #${this.id} not set...`);
    }

    this.broadcast({
      type: Message.Kosk,
      data: {
        kosk: this.kosk,
      },
    });
  }

  generateCommitments(): Point[] {
    const { coefficients } = this.polynomial;
    let commitments = coefficients.map((coef) => this.curve.G.scalarMul(coef));

    if (this.epoch > 0) {
      // Don't compute a commitment for the first coefficient, as `0`
      //  doesn't have a (modular) multiplicative inverse.
      commitments = coefficients.slice(1).map((coef) =>
        this.curve.G.scalarMul(coef)
      );
    }

    this.commitments = commitments;

    return this.commitments;
  }

  broadcastCommitments(): void {
    if (!this.commitments) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    this.broadcast({
      type: Message.Commitments,
      data: {
        commitments: this.commitments,
      },
    });
  }

  async verifyKosks(): Promise<boolean> {
    const promises: Promise<boolean>[] = [];
    for (const key of Object.keys(this.parties)) {
      const id = Number(key);
      promises.push(this.verifyKosk(id));
    }

    const results = await Promise.all(promises);

    return results.every((result) => result === true);
  }

  sendEvaluations(): void {
    const evaluations = this.computeEvaluations();

    for (const evaluation of evaluations) {
      const { id, y } = evaluation;

      this.send(id, {
        type: Message.Evaluation,
        data: {
          y,
        },
      });
    }
  }

  verifyEvaluations(): boolean {
    const results: boolean[] = [];

    for (const key of Object.keys(this.parties)) {
      const id = Number(key);
      results.push(this.verifyEvaluation(id));
    }

    return results.every((result) => result === true);
  }

  calculateSecretShare(): bigint {
    const ownY = this.polynomial.evaluate(BigInt(this.id));

    let result = ownY;
    for (const [key, data] of Object.entries(this.parties)) {
      if (!data.y) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing the Y value from party #${id}...`,
        );
      }

      result = mod(result + data.y, this.curve.n);
    }

    // Refresh secret share if we're past the initial epoch.
    if (this.epoch > 0) {
      // deno-lint-ignore no-non-null-assertion
      result = mod(this.secretShare! + result, this.curve.n);
    }

    this.secretShare = result;

    return this.secretShare;
  }

  calculatePublicKey(): Point {
    if (!this.commitments) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    const ownZeroCommitment = this.commitments[0];

    let result = ownZeroCommitment;
    for (const [key, data] of Object.entries(this.parties)) {
      if (!data.commitments?.length) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing commitments from party #${id}...`,
        );
      }

      const zeroCommitment = data.commitments[0];
      result = result.add(zeroCommitment);
    }

    this.publicKey = result;

    return this.publicKey;
  }

  private computeEvaluations(): { id: Id; y: bigint }[] {
    const results: { id: Id; y: bigint }[] = [];

    for (const [key] of Object.keys(this.parties)) {
      const id = Number(key);
      const y = this.computeEvaluation(id);
      results.push({ id, y });
    }

    return results;
  }

  private async verifyKosk(id: Id): Promise<boolean> {
    const { kosk, commitments } = this.parties[id];
    if (!kosk || !commitments) {
      return false;
    }

    const schnorr = new SchnorrSignature();

    const pk = commitments[0];
    return await schnorr.verify(pk, pk2Bytes(pk), kosk);
  }

  private computeEvaluation(id: Id): bigint {
    return this.polynomial.evaluate(BigInt(id));
  }

  private verifyEvaluation(id: Id): boolean {
    const { commitments, y } = this.parties[id];
    if (!commitments || !y) {
      return false;
    }

    const left = this.curve.G.scalarMul(y);
    const right = commitments.reduce(
      (accum, comm, idx) =>
        accum.add(
          comm.scalarMul(BigInt(this.id ** (idx + (this.epoch > 0 ? 1 : 0)))),
        ),
      Point.infinity(this.curve),
    );

    return left.x === right.x && left.y === right.y;
  }

  private generatePolynomial(): Polynomial {
    const polynomial = new Polynomial(this.t - 1, this.curve.n);

    if (this.epoch > 0) {
      polynomial.coefficients[0] = 0n;
    }

    this.polynomial = polynomial;

    return this.polynomial;
  }
}

type Id = number;

type Send = (to: Id, payload: Payload) => void;

type Receive = (from: Id, payload: Payload) => void;

type PartyData = {
  [id: Id]: {
    send?: Send;
    receive?: Receive;
    kosk?: Signature;
    commitments?: Point[];
    y?: bigint;
  };
};

interface P2P {
  connect(other: Party): void;
  send: Send;
  receive: Receive;
  broadcast(payload: Payload): void;
}

type Payload = {
  type: Message.Kosk;
  data: {
    kosk: Signature;
  };
} | {
  type: Message.Commitments;
  data: {
    commitments: Point[];
  };
} | {
  type: Message.Evaluation;
  data: {
    y: bigint;
  };
};

enum Message {
  Kosk,
  Commitments,
  Evaluation,
}
