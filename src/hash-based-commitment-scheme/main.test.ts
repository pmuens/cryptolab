import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import { createCommitment, verifyCommitment } from "./main.ts";

describe("Hash-Based Commitment Scheme", () => {
  it("should verify a valid commitment", async () => {
    const v = 42;
    const { c, r } = await createCommitment(v);

    const isValid = await verifyCommitment(v, r, c);

    expect(isValid).toBe(true);
  });

  it("shouldn't verify an invalid commitment", async () => {
    const v = 42;
    const c = new Uint8Array([1, 2, 3, 4, 5]);
    const { r } = await createCommitment(v);

    const isValid = await verifyCommitment(v, r, c);

    expect(isValid).toBe(false);
  });
});
