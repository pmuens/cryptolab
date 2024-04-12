import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { ECDSA } from "./ecdsa.ts";

describe("ECDSA", () => {
  // See: https://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa#playing-with-ecdsa
  it("should verify a valid signature when the private key is known", async () => {
    const privateKey = BigInt(
      "0x9f4c9eb899bd86e0e83ecca659602a15b2edb648e2ae4ee4a256b17bb29a1a1e",
    );
    const ecdsa = new ECDSA(privateKey);
    const publicKey = ecdsa.pk;

    const encoder = new TextEncoder();
    const message = encoder.encode("Hello!");
    const isValid = await ecdsa.verify(publicKey, message, {
      r: BigInt(
        "0xddcb8b5abfe46902f2ac54ab9cd5cf205e359c03fdf66ead1130826f79d45478",
      ),
      s: BigInt(
        "0x551a5b2cd8465db43254df998ba577cb28e1ee73c5530430395e4fba96610151",
      ),
    });

    expect(isValid).toBe(true);
  });

  it("should generate a valid signature when the private key is known", async () => {
    const privateKey = BigInt(
      "0xe32868331fa8ef0138de0de85478346aec5e3912b6029ae71691c384237a3eeb",
    );
    const ecdsa = new ECDSA(privateKey);
    const publicKey = ecdsa.pk;

    const message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const signature = await ecdsa.sign(message);
    const isValid = await ecdsa.verify(publicKey, message, signature);

    expect(isValid).toBe(true);
  });

  it("should generate a signature when the private key is randomized", async () => {
    const ecdsa = new ECDSA();
    const publicKey = ecdsa.pk;

    const message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const signature = await ecdsa.sign(message);
    const isValid = await ecdsa.verify(publicKey, message, signature);

    expect(isValid).toBe(true);
  });
});
