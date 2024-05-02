import { assert } from "$std/assert/assert.ts";

import { Point } from "../shared/ecc/point.ts";
import { Curve } from "../shared/ecc/curve.ts";
import { mod, pk2Bytes } from "../shared/utils.ts";
import { Polynomial } from "../shared/polynomial.ts";
import { SchnorrSignature, Signature } from "../schnorr-signature/main.ts";

// The following is an implementation of the Distributed Key Generation algorithm described in the
//  [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852) paper.
export class DKG {
  parties: Party[] = [];

  static async init(t: number, n: number, curve: Curve): Promise<DKG> {
    const promises: Promise<Party>[] = [];

    for (let i = 0; i < n; i++) {
      const id = i + 1;
      promises.push(Party.init(id, t, curve));
    }

    const parties = await Promise.all(promises);

    return new DKG(parties);
  }

  async run(): Promise<Point> {
    this.establishConnections();

    // Round #1.
    this.broadcastKosk();
    this.broadcastCommitments();
    await this.verifyKosks();

    // Round #2.
    this.sendEvaluations();
    this.verifyEvaluations();
    this.calculateSecretShare();
    return this.calculatePublicKey();
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

  private broadcastKosk(): void {
    for (const party of this.parties) {
      party.broadcastKosk();
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

  private constructor(parties: Party[]) {
    this.parties = parties;
  }
}

export class Party implements P2P {
  id: Id;
  curve: Curve;
  polynomial: Polynomial;
  f: (x: bigint) => bigint;
  kosk: Signature;
  commitments: Point[];
  schnorr: SchnorrSignature;
  secretShare?: bigint;
  publicKey?: Point;
  parties: PartyData = {};

  static async init(
    id: number,
    t: number,
    curve: Curve,
  ): Promise<Party> {
    if (id <= 0) {
      throw new Error(`The party's id needs to be >= 1 but is ${id}...`);
    }
    const polynomial = new Polynomial(t - 1, curve.n);

    const coefficients = polynomial.coefficients;
    const commitments = coefficients.map((coef) => curve.G.scalarMul(coef));

    const sk = polynomial.coefficients[0];
    const pk = commitments[0];
    const schnorr = new SchnorrSignature(sk, curve);

    assert(schnorr.curve.name === curve.name);
    assert(schnorr.pk.x === pk.x && schnorr.pk.y === pk.y);

    const kosk = await schnorr.sign(pk2Bytes(pk));

    return new Party(
      id,
      curve,
      polynomial,
      commitments,
      kosk,
      schnorr,
    );
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

  broadcastKosk(): void {
    this.broadcast({
      type: Message.Kosk,
      data: {
        kosk: this.kosk,
      },
    });
  }

  broadcastCommitments(): void {
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
    const ownY = this.f(BigInt(this.id));

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

    this.secretShare = result;

    return this.secretShare;
  }

  calculatePublicKey(): Point {
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

    const pk = commitments[0];
    return await this.schnorr.verify(pk, pk2Bytes(pk), kosk);
  }

  private computeEvaluation(id: Id): bigint {
    return this.f(BigInt(id));
  }

  private verifyEvaluation(id: Id): boolean {
    const { commitments, y } = this.parties[id];
    if (!commitments || !y) {
      return false;
    }

    const left = this.curve.G.scalarMul(y);
    const right = commitments.reduce(
      (accum, comm, idx) => accum.add(comm.scalarMul(BigInt(this.id ** idx))),
      Point.infinity(this.curve),
    );

    return left.x === right.x && left.y === right.y;
  }

  private constructor(
    id: Id,
    curve: Curve,
    polynomial: Polynomial,
    commitments: Point[],
    kosk: Signature,
    schnorr: SchnorrSignature,
  ) {
    this.id = id;
    this.curve = curve;
    this.polynomial = polynomial;
    this.commitments = commitments;
    this.kosk = kosk;
    this.f = polynomial.evaluate.bind(this.polynomial);
    this.schnorr = schnorr;
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
