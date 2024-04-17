import { crypto, DigestAlgorithm } from "$std/crypto/mod.ts";

import { buf2hex, getRandomNumber, int2BytesBe } from "../ecc/utils.ts";

export class HashCommitment {
  algo: DigestAlgorithm;

  constructor(algo: DigestAlgorithm = "SHA-256") {
    this.algo = algo;
  }

  async create(
    v: bigint,
  ): Promise<{ r: bigint; c: Uint8Array }> {
    const r = getRandomNumber();
    const digest = await this.createDigest(v, r);
    const c = new Uint8Array(digest);

    return {
      r,
      c,
    };
  }

  async verify(
    v: bigint,
    r: bigint,
    c: Uint8Array,
  ): Promise<boolean> {
    const digest = await this.createDigest(v, r);
    const cPrime = new Uint8Array(digest);

    return buf2hex(c) === buf2hex(cPrime);
  }

  private createDigest(v: bigint, r: bigint): Promise<ArrayBuffer> {
    const vBytes = int2BytesBe(v);
    const rBytes = int2BytesBe(r);

    const data = new Uint8Array(vBytes.length + rBytes.length);

    data.set(vBytes);
    data.set(rBytes, vBytes.length);

    return crypto.subtle.digest(this.algo, data);
  }
}
