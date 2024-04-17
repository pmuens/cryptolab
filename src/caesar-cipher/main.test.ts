import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { CaesarCipher } from "./main.ts";

describe("Caesar Cipher", () => {
  it("should encrypt and decrypt", () => {
    const key = 3;
    const message = "hello";

    const caesar = new CaesarCipher(key);

    const ciphertext = caesar.encrypt(message);
    const plaintext = caesar.decrypt(ciphertext);

    expect(plaintext).toBe(message);
  });
});
