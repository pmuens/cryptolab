import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { pk2Bytes } from "../shared/utils.ts";
import { SchnorrSignatureAggregation } from "./main.ts";
import { SchnorrSignature } from "../schnorr-signature/main.ts";

describe("Schnorr Signature Aggregation", () => {
  it("should generate a valid signature with multiple participants", async () => {
    const alice = new SchnorrSignature();
    const bob = new SchnorrSignature();
    const carol = new SchnorrSignature();

    const schnorrClassic = new SchnorrSignature();
    const schnorrAggregated = await SchnorrSignatureAggregation.init([
      { schnorr: alice, kosk: await alice.sign(pk2Bytes(alice.pk)) },
      { schnorr: bob, kosk: await bob.sign(pk2Bytes(bob.pk)) },
      { schnorr: carol, kosk: await carol.sign(pk2Bytes(carol.pk)) },
    ]);
    const publicKey = schnorrAggregated.pk;

    const message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const signature = await schnorrAggregated.sign(message);
    const isValid = await schnorrClassic.verify(publicKey, message, signature);

    expect(isValid).toBe(true);
  });
});
