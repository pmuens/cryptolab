import { Curve } from "../shared/ecc/curve.ts";
import { Point } from "../shared/ecc/point.ts";
import { mod, pk2Bytes } from "../shared/utils.ts";
import { Nonce } from "../schnorr-signature/main.ts";
import { Id, P2P, Receive, Send } from "../shared/types.ts";
import { SchnorrSignature, Signature } from "../schnorr-signature/main.ts";

export class Aggregator {
  parties: Party[];

  constructor(n: number, curve: Curve) {
    const parties: Party[] = [];

    for (let i = 0; i < n; i++) {
      const id = i + 1;
      parties.push(new Party(id, curve));
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
    for await (const party of this.parties) {
      party.broadcastPk();
      await party.setKosk();
      party.broadcastKosk();
    }
    const pks: Point[] = [];
    for await (const party of this.parties) {
      await party.verifyKosks();
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

  async sign(message: Uint8Array): Promise<Signature> {
    for (const party of this.parties) {
      party.setNonce();
      party.broadcastR();
    }
    for await (const party of this.parties) {
      party.setR();
      await party.setE(message);
      party.broadcastE();
    }
    const sigs: Signature[] = [];
    for (const party of this.parties) {
      sigs.push(party.calculateSignature());
    }

    // See: https://stackoverflow.com/a/35568895
    const allSigsEqual = sigs.every((sig) =>
      sig.R.x === sigs[0].R.x && sig.R.y === sigs[0].R.y && sig.e === sigs[0].e
    );

    if (!allSigsEqual) {
      throw new Error("Signatures aren't all equal...");
    }

    return sigs[0];
  }
}

class Party implements P2P<Party, Payload> {
  id: number;
  curve: Curve;
  schnorr: SchnorrSignature;
  kosk?: Signature;
  nonce?: Nonce;
  e?: bigint;
  publicKey?: Point;
  R?: Point;
  partyData: Data = {};

  constructor(
    id: Id,
    curve: Curve,
  ) {
    if (id <= 0) {
      throw new Error(`The party's id needs to be >= 1 but is ${id}...`);
    }

    const sk = undefined;

    this.id = id;
    this.curve = curve;
    this.schnorr = new SchnorrSignature(sk, curve);
  }

  async setKosk(): Promise<void> {
    const { pk } = this.schnorr;
    this.kosk = await this.schnorr.sign(pk2Bytes(pk));
  }

  broadcastPk(): void {
    this.broadcast({
      type: Message.Pk,
      data: {
        pk: this.schnorr.pk,
      },
    });
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

  async verifyKosks(): Promise<void> {
    const promises: Promise<boolean>[] = [];

    for (const key of Object.keys(this.partyData)) {
      const id = Number(key);
      const { pk, kosk } = this.partyData[id];
      if (!pk || !kosk) {
        promises.push(Promise.resolve(false));
      } else {
        promises.push(this.schnorr.verify(pk, pk2Bytes(pk), kosk));
      }
    }
    const results = await Promise.all(promises);

    const allValid = results.every((result) => result === true);
    if (!allValid) {
      throw new Error("Error validating KOSKs...");
    }
  }

  setPublicKey(): void {
    let result = this.schnorr.pk;

    for (const [key, value] of Object.entries(this.partyData)) {
      if (!value.pk) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing public key from party #${id}...`,
        );
      }

      result = result.add(value.pk);
    }

    this.publicKey = result;
  }

  setNonce(): void {
    this.nonce = this.schnorr.createNonce();
  }

  broadcastR(): void {
    if (!this.nonce) {
      throw new Error(`Nonce of party #${this.id} not set...`);
    }

    this.broadcast({
      type: Message.R,
      data: {
        R: this.nonce.R,
      },
    });
  }

  setR(): void {
    if (!this.nonce) {
      throw new Error(`Nonce of party #${this.id} not set...`);
    }

    let R = this.nonce.R;

    for (const [key, value] of Object.entries(this.partyData)) {
      if (!value.R) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing value R from party #${id}...`,
        );
      }

      R = R.add(value.R);
    }

    this.R = R;
  }

  async setE(message: Uint8Array): Promise<void> {
    if (!this.publicKey) {
      throw new Error(`Public key of party #${this.id} not set...`);
    }
    if (!this.nonce) {
      throw new Error(`Nonce of party #${this.id} not set...`);
    }
    if (!this.R) {
      throw new Error(`R value of party #${this.id} not set...`);
    }

    const c = await this.schnorr.createChallenge(
      this.publicKey,
      this.R,
      message,
    );

    this.e = mod(
      this.nonce.r + mod(c * this.schnorr.sk, this.curve.n),
      this.curve.n,
    );
  }

  broadcastE(): void {
    if (!this.e) {
      throw new Error(`E value of party #${this.id} not set...`);
    }

    this.broadcast({
      type: Message.E,
      data: {
        e: this.e,
      },
    });
  }

  calculateSignature(): Signature {
    if (!this.e) {
      throw new Error(`e value of party #${this.id} not set...`);
    }
    if (!this.R) {
      throw new Error(`R value of party #${this.id} not set...`);
    }

    const es: bigint[] = [];

    es.push(this.e);

    for (const [key, value] of Object.entries(this.partyData)) {
      if (!value.e) {
        const id = Number(key);
        throw new Error(
          `Party #${this.id} is missing value e from party #${id}...`,
        );
      }

      es.push(value.e);
    }

    const e = es.reduce((accum, e) => {
      return mod(accum + e, this.curve.n);
    }, 0n);

    return {
      R: this.R,
      e,
    };
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
      case Message.Pk:
        this.partyData[from].pk = payload.data.pk;
        break;
      case Message.Kosk:
        this.partyData[from].kosk = payload.data.kosk;
        break;
      case Message.R:
        this.partyData[from].R = payload.data.R;
        break;
      case Message.E:
        this.partyData[from].e = payload.data.e;
        break;
    }
  }
}

type Data = {
  [id: Id]: {
    send?: Send<Payload>;
    receive?: Receive<Payload>;
    pk?: Point;
    kosk?: Signature;
    R?: Point;
    e?: bigint;
  };
};

type Payload = {
  type: Message.Pk;
  data: {
    pk: Point;
  };
} | {
  type: Message.Kosk;
  data: {
    kosk: Signature;
  };
} | {
  type: Message.R;
  data: {
    R: Point;
  };
} | {
  type: Message.E;
  data: {
    e: bigint;
  };
};

enum Message {
  Pk,
  Kosk,
  R,
  E,
}
