import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { decrypt, encrypt } from "./main.ts";

describe("One-Time-Pad", () => {
  it("should encrypt and decrypt", () => {
    const key = 0b1011;
    const message = 0b1010;

    const ciphertext = encrypt(key, message);
    const plaintext = decrypt(key, ciphertext);

    expect(plaintext).toBe(message);
  });

  it("should demonstrate key extraction via CPA", () => {
    const key = 0b1011;
    const message = 0b1010;

    const ciphertext = encrypt(key, message);
    const keyRecovered = ciphertext ^ message;

    expect(keyRecovered).toBe(key);
  });

  it("should demonstrate XORed plaintexts", () => {
    const key = 0b1011;
    const messageOne = 0b1010;
    const messageTwo = 0b1101;

    const ciphertextOne = encrypt(key, messageOne);
    const ciphertextTwo = encrypt(key, messageTwo);
    const xoredPlaintexts = ciphertextOne ^ ciphertextTwo;

    expect(xoredPlaintexts).toBe(messageOne ^ messageTwo);
  });
});
