const ALPHABET = [
  "a",
  "b",
  "c",
  "d",
  "e",
  "f",
  "g",
  "h",
  "i",
  "j",
  "k",
  "l",
  "m",
  "n",
  "o",
  "p",
  "q",
  "r",
  "s",
  "t",
  "u",
  "v",
  "w",
  "x",
  "y",
  "z",
];

export function encrypt(key: number, plaintext: string): string {
  const plaintextArray = [...plaintext.toLocaleLowerCase()];

  const plaintextIndexed = plaintextArray.map((char) => ALPHABET.indexOf(char));
  const ciphertextIndexed = plaintextIndexed.map(
    (idx) => (idx + key) % ALPHABET.length,
  );

  const ciphertext = ciphertextIndexed.reduce(
    (result, index) => (result += ALPHABET[index]),
    "",
  );

  return ciphertext;
}

export function decrypt(key: number, ciphertext: string): string {
  const ciphertextArray = [...ciphertext];

  const ciphertextIndexed = ciphertextArray.map((char) =>
    ALPHABET.indexOf(char)
  );
  const plaintextIndexed = ciphertextIndexed.map(
    (idx) => (idx - key) % ALPHABET.length,
  );

  const plaintext = plaintextIndexed.reduce(
    (result, index) => (result += ALPHABET[index]),
    "",
  );

  return plaintext;
}
