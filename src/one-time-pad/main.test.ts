import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { OTP } from "./main.ts";

describe("One-Time-Pad", () => {
  it("should encrypt and decrypt", () => {
    const key = 0b1011n;
    const message = 0b1010n;

    const otp = new OTP(key);

    const ciphertext = otp.encrypt(message);
    const plaintext = otp.decrypt(ciphertext);

    expect(plaintext).toBe(message);
  });

  it("should demonstrate key extraction via CPA", () => {
    const key = 0b1011n;
    const message = 0b1010n;

    const otp = new OTP(key);

    const ciphertext = otp.encrypt(message);
    const keyRecovered = ciphertext ^ message;

    expect(keyRecovered).toBe(key);
  });

  it("should demonstrate XORed plaintexts", () => {
    const key = 0b1011n;
    const messageOne = 0b1010n;
    const messageTwo = 0b1101n;

    const otp = new OTP(key);

    const ciphertextOne = otp.encrypt(messageOne);
    const ciphertextTwo = otp.encrypt(messageTwo);
    const xoredPlaintexts = ciphertextOne ^ ciphertextTwo;

    expect(xoredPlaintexts).toBe(messageOne ^ messageTwo);
  });
});
