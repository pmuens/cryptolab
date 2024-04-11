import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { decrypt, encrypt } from "./main.ts";

describe("Caesar Cipher", () => {
  it("should encrypt and decrypt", () => {
    const key = 3;
    const message = "hello";

    const ciphertext = encrypt(key, message);
    const plaintext = decrypt(key, ciphertext);

    expect(plaintext).toBe(message);
  });
});
