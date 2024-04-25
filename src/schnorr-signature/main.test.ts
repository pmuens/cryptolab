import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { SchnorrSignature } from "./main.ts";

describe("Schnorr Signature", () => {
  it("should generate a valid signature when the private key is known", async () => {
    const privateKey = BigInt(
      "0xe32868331fa8ef0138de0de85478346aec5e3912b6029ae71691c384237a3eeb",
    );
    const schnorr = new SchnorrSignature(privateKey);
    const publicKey = schnorr.pk;

    const message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const signature = await schnorr.sign(message);
    const isValid = await schnorr.verify(publicKey, message, signature);

    expect(isValid).toBe(true);
  });

  it("should generate a valid signature when the private key is randomized", async () => {
    const schnorr = new SchnorrSignature();
    const publicKey = schnorr.pk;

    const message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const signature = await schnorr.sign(message);
    const isValid = await schnorr.verify(publicKey, message, signature);

    expect(isValid).toBe(true);
  });
});
