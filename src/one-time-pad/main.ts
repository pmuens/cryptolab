export function encrypt(key: number, plaintext: number): number {
  if (!meetsLengthRequirement(key, plaintext)) {
    throw new Error(
      "For the One-Time-Pad to be secure the key and the ciphertext need to have the same length...",
    );
  }

  const ciphertext = key ^ plaintext;
  return ciphertext;
}

export function decrypt(key: number, ciphertext: number): number {
  if (!meetsLengthRequirement(key, ciphertext)) {
    throw new Error(
      "For the One-Time-Pad to be secure the key and the ciphertext need to have the same length...",
    );
  }

  const plaintext = key ^ ciphertext;
  return plaintext;
}

function meetsLengthRequirement(key: number, text: number): boolean {
  // Get number of desired bits.
  //  Can be taken form key or plaintext as both have the same length.
  const binaryLength = key.toString(2).length;

  const keyBinaryString = toBinaryString(binaryLength, text);
  const textBinaryString = toBinaryString(binaryLength, text);

  if (keyBinaryString.length !== textBinaryString.length) {
    return false;
  }
  return true;
}

function toBinaryString(binaryLength: number, text: number): string {
  const binaryResult = text.toString(2); // Turn into a binary string.
  return binaryResult.padStart(binaryLength, "0"); // Add padding in front (if necessary).
}
