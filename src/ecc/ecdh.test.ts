import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { ECDH } from "./ecdh.ts";
import { int2Hex } from "./utils.ts";

describe("ECDH", () => {
  // See: https://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa#playing-with-ecdh
  it("should derive a shared secret when using known private keys", () => {
    const ecdhAlice = new ECDH(
      BigInt(
        "0xe32868331fa8ef0138de0de85478346aec5e3912b6029ae71691c384237a3eeb",
      ),
    );

    const ecdhBob = new ECDH(
      BigInt(
        "0xcef147652aa90162e1fff9cf07f2605ea05529ca215a04350a98ecc24aa34342",
      ),
    );

    const sharedSecretAlice = ecdhAlice.deriveSecret(ecdhBob.pk);
    const sharedSecretBob = ecdhBob.deriveSecret(ecdhAlice.pk);

    expect(sharedSecretAlice.x).toBe(sharedSecretBob.x);
    expect(sharedSecretAlice.y).toBe(sharedSecretBob.y);

    expect(
      int2Hex(sharedSecretAlice.x),
    ).toBe(
      "0x3e2ffbc3aa8a2836c1689e55cd169ba638b58a3a18803fcf7de153525b28c3cd",
    );
    expect(
      int2Hex(sharedSecretAlice.y),
    ).toBe(
      "0x043ca148c92af58ebdb525542488a4fe6397809200fe8c61b41a105449507083",
    );
  });

  it("should derive a shared secret when using random private keys", () => {
    const ecdhAlice = new ECDH();
    const ecdhBob = new ECDH();

    const sharedSecretAlice = ecdhAlice.deriveSecret(ecdhBob.pk);
    const sharedSecretBob = ecdhBob.deriveSecret(ecdhAlice.pk);

    expect(sharedSecretAlice.x).toBe(sharedSecretBob.x);
    expect(sharedSecretAlice.y).toBe(sharedSecretBob.y);
  });
});
