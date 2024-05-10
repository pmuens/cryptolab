import { expect } from "$std/expect/mod.ts";
import { beforeAll, describe, it } from "$std/testing/bdd.ts";

import { Aggregator } from "./main.ts";
import { Point } from "../shared/ecc/point.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";
import { SchnorrSignature } from "../schnorr-signature/main.ts";

describe("Schnorr Signature Aggregation", () => {
  let curve: Secp256k1;

  beforeAll(() => {
    curve = new Secp256k1();
  });

  it("should generate a shared public key", async () => {
    const aggregator = new Aggregator(3, curve);

    const pk = await aggregator.keygen();

    const pkPrime = aggregator.parties.reduce<Point>(
      (accum, party) => accum.add(party.schnorr.pk),
      Point.infinity(curve),
    );

    expect(pk.x).toEqual(pkPrime.x);
    expect(pk.y).toEqual(pkPrime.y);
  });

  it("should sign a message collaboratively", async () => {
    const aggregator = new Aggregator(3, curve);

    const pk = await aggregator.keygen();

    const msg = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const sig = await aggregator.sign(msg);

    const schnorr = new SchnorrSignature();
    const isValid = await schnorr.verify(pk, msg, sig);

    expect(isValid).toBe(true);
  });
});
