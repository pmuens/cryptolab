import { assert } from "$std/assert/assert.ts";

import { Point } from "../shared/ecc/point.ts";
import { Curve } from "../shared/ecc/curve.ts";
import { mod, pk2Bytes } from "../shared/utils.ts";
import { Polynomial } from "../shared/polynomial.ts";
import { Id, P2P, Receive, Send } from "../shared/types.ts";
import { SchnorrSignature, Signature } from "../schnorr-signature/main.ts";

export class DKG {
  parties: Party[];

  constructor(t: number, n: number, curve: Curve) {
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

  async keygen(): Promise<Point> {
    // --- Round #1 ---
    for await (const party of this.parties) {
      party.setPolynomial();
      party.setCommitments();
      await party.setKosk();
      party.broadcastKosk();
      party.broadcastCommitments();
    }
    for await (const party of this.parties) {
      await party.verifyKosks();
    }

    // --- Round #2 ---
    for (const party of this.parties) {
      for (const key of Object.keys(party.partyData)) {
        const id = Number(key);
        const y = party.evaluatePolynomial(id);
        party.sendEvaluation(id, y);
      }
    }
    const pks: Point[] = [];
    for (const party of this.parties) {
      party.verifyEvaluations();
      party.setSecretShare();
      party.setPublicKey();
      if (!party.publicKey) {
        throw new Error(`Public Key of party #${party.id} not set...`);
      }
      pks.push(party.publicKey);
    }

    // See: https://stackoverflow.com/a/35568895
    const allPksEqual = pks.every((pk) =>
      pk.x === pks[0].x && pk.y === pks[0].y
    );

    if (!allPksEqual) {
      throw new Error("Public Keys aren't all equal...");
    }

    return pks[0];
  }
}

export class Party implements P2P<Party, Payload> {
  id: Id;
  t: number;
  curve: Curve;
  polynomial?: Polynomial;
  commitments?: Point[];
  kosk?: Signature;
  secretShare?: bigint;
  publicKey?: Point;
  partyData: Data = {};

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
  }

  setPolynomial(): void {
    this.polynomial = new Polynomial(this.t - 1, this.curve.n);
  }

  setCommitments(): void {
    if (!this.polynomial) {
      throw new Error(`Polynomial of party #${this.id} not set...`);
    }
    this.commitments = this.polynomial.coefficients.map((coef) =>
      this.curve.G.scalarMul(coef)
    );
  }

  async setKosk(): Promise<void> {
    if (!this.polynomial) {
      throw new Error(`Polynomial of party #${this.id} not set...`);
    }
    if (!this.commitments || !this.commitments.length) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    const sk = this.polynomial.coefficients[0];
    const pk = this.commitments[0];
    const schnorr = new SchnorrSignature(sk, this.curve);

    assert(schnorr.curve.name === this.curve.name);
    assert(schnorr.pk.x === pk.x && schnorr.pk.y === pk.y);

    this.kosk = await schnorr.sign(pk2Bytes(pk));
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

  broadcastCommitments(): void {
    if (!this.commitments || !this.commitments.length) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    this.broadcast({
      type: Message.Commitments,
      data: {
        commitments: this.commitments,
      },
    });
  }

  async verifyKosks(): Promise<void> {
    const schnorr = new SchnorrSignature(1n, this.curve);

    const promises: Promise<boolean>[] = [];
    for (const key of Object.keys(this.partyData)) {
      const id = Number(key);
      const { kosk, commitments } = this.partyData[id];
      if (!kosk || !commitments) {
        promises.push(Promise.resolve(false));
      } else {
        const pk = commitments[0];
        promises.push(schnorr.verify(pk, pk2Bytes(pk), kosk));
      }
    }
    const results = await Promise.all(promises);

    const allValid = results.every((result) => result === true);
    if (!allValid) {
      throw new Error("Error validating KOSKs...");
    }
  }

  evaluatePolynomial(x: number): bigint {
    if (!this.polynomial) {
      throw new Error(`Polynomial of party #${this.id} not set...`);
    }
    return this.polynomial.evaluate(BigInt(x));
  }

  sendEvaluation(id: Id, y: bigint): void {
    this.send(id, {
      type: Message.Evaluation,
      data: {
        y,
      },
    });
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
                BigInt(this.id ** idx),
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

    this.secretShare = result;
  }

  setPublicKey(): void {
    if (!this.commitments) {
      throw new Error(`Commitments of party #${this.id} not set...`);
    }

    const ownZeroCommitment = this.commitments[0];

    let result = ownZeroCommitment;
    for (const [key, value] of Object.entries(this.partyData)) {
      if (!value.commitments || !value.commitments.length) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing commitments from party #${id}...`,
        );
      }

      const zeroCommitment = value.commitments[0];
      result = result.add(zeroCommitment);
    }

    this.publicKey = result;
  }

  connect(party: Party): void {
    const id = party.id;
    const send = party.send.bind(party);
    const receive = party.receive.bind(party);

    this.partyData[id] = {
      send,
      receive,
    };
  }

  broadcast(payload: Payload): void {
    for (const key of Object.keys(this.partyData)) {
      const id = Number(key);
      this.send(id, payload);
    }
  }

  send(to: Id, payload: Payload): void {
    // deno-lint-ignore no-non-null-assertion
    this.partyData[to].receive!(this.id, payload);
  }

  receive(from: Id, payload: Payload): void {
    switch (payload.type) {
      case Message.Kosk:
        this.partyData[from].kosk = payload.data.kosk;
        break;
      case Message.Commitments:
        this.partyData[from].commitments = payload.data.commitments;
        break;
      case Message.Evaluation:
        this.partyData[from].y = payload.data.y;
        break;
    }
  }
}

type Data = {
  [id: Id]: {
    send?: Send<Payload>;
    receive?: Receive<Payload>;
    kosk?: Signature;
    commitments?: Point[];
    y?: bigint;
  };
};

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
