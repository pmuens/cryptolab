export class OTP {
  key: bigint;

  constructor(key: bigint) {
    this.key = key;
  }

  encrypt(plaintext: bigint): bigint {
    if (!this.meetsLengthRequirement(plaintext)) {
      throw new Error(
        "For the One-Time-Pad to be secure the key and the ciphertext need to have the same length...",
      );
    }

    return this.key ^ plaintext;
  }

  decrypt(ciphertext: bigint): bigint {
    if (!this.meetsLengthRequirement(ciphertext)) {
      throw new Error(
        "For the One-Time-Pad to be secure the key and the ciphertext need to have the same length...",
      );
    }

    return this.key ^ ciphertext;
  }

  private meetsLengthRequirement(text: bigint): boolean {
    // Get number of desired bits.
    //  Can be taken form key or plaintext as both have the same length.
    const binaryLength = this.key.toString(2).length;

    const keyBinaryString = toBinaryString(binaryLength, text);
    const textBinaryString = toBinaryString(binaryLength, text);

    if (keyBinaryString.length !== textBinaryString.length) {
      return false;
    }
    return true;
  }
}

function toBinaryString(binaryLength: number, text: bigint): string {
  // Turn into a binary string.
  const binaryResult = text.toString(2);
  // Add padding in front (if necessary).
  return binaryResult.padStart(binaryLength, "0");
}
