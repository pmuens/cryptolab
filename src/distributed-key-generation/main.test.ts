import { expect } from "$std/expect/mod.ts";
import { beforeAll, describe, it } from "$std/testing/bdd.ts";

import { DKG } from "./main.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";
import { recoverSecret } from "../shared/testing/utils.ts";

describe("Distributed Key Generation", () => {
  let curve: Secp256k1;

  beforeAll(() => {
    curve = new Secp256k1();
  });

  it("should derive a key pair and be able to recover the private key if the threshold is met", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = new DKG(t, n, curve);
    const pk = await dkg.keygen();

    const sk = recoverSecret(dkg.parties, t, curve.n);
    const pkPrime = curve.G.scalarMul(sk);

    expect(pk.x).toEqual(pkPrime.x);
    expect(pk.y).toEqual(pkPrime.y);
  });

  it("should derive a key pair and be able to recover the private key if the threshold is exceeded", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = new DKG(t, n, curve);
    const pk = await dkg.keygen();

    const sk = recoverSecret(dkg.parties, n, curve.n);
    const pkPrime = curve.G.scalarMul(sk);

    expect(pk.x).toEqual(pkPrime.x);
    expect(pk.y).toEqual(pkPrime.y);
  });

  it("should derive a key pair and not be able to recover the private key if the threshold is not met", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = new DKG(t, n, curve);
    const pk = await dkg.keygen();

    const sk = recoverSecret(dkg.parties, t - 1, curve.n);
    const pkPrime = curve.G.scalarMul(sk);

    expect(pk.x).not.toEqual(pkPrime.x);
    expect(pk.y).not.toEqual(pkPrime.y);
  });
});
