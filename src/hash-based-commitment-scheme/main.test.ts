import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { HashCommitment } from "./main.ts";

describe("Hash-Based Commitment Scheme", () => {
  it("should verify a valid commitment", async () => {
    const v = 42n;
    const commitment = new HashCommitment();

    const { c, r } = await commitment.create(v);
    const isValid = await commitment.verify(v, r, c);

    expect(isValid).toBe(true);
  });

  it("shouldn't verify an invalid commitment", async () => {
    const v = 42n;
    const commitment = new HashCommitment();

    const c = new Uint8Array([1, 2, 3, 4, 5]);

    const { r } = await commitment.create(v);
    const isValid = await commitment.verify(v, r, c);

    expect(isValid).toBe(false);
  });
});
