import { expect } from "$std/expect/mod.ts";
import { beforeAll, describe, it } from "$std/testing/bdd.ts";

import { DKG, Party } from "./main.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";
import { Lagrange } from "../lagrange-interpolation/main.ts";

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
    const pk = await dkg.run();

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
    const pk = await dkg.run();

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
    const pk = await dkg.run();

    const sk = recoverSecret(dkg.parties, t - 1, curve.n);
    const pkPrime = curve.G.scalarMul(sk);

    expect(pk.x).not.toEqual(pkPrime.x);
    expect(pk.y).not.toEqual(pkPrime.y);
  });

  it("should refresh secret shares while preserving the private- and public key", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = new DKG(t, n, curve);
    const pk = await dkg.run();

    const secretShares = dkg.parties.map((party) => party.secretShare);

    dkg.refresh();

    // Each party's secret share should be different.
    const secretSharesPrime = dkg.parties.map((party) => party.secretShare);
    expect(secretShares).not.toEqual(secretSharesPrime);

    // The secret that can be recovered with the refreshed secret shares
    // should still allow for the computation of the same public key.
    const sk = recoverSecret(dkg.parties, t, curve.n);
    const pkPrime = curve.G.scalarMul(sk);

    expect(pk.x).toEqual(pkPrime.x);
    expect(pk.y).toEqual(pkPrime.y);
  });
});

function recoverSecret(
  parties: Party[],
  t: number,
  modulus: bigint,
): bigint {
  const lagrange = new Lagrange(modulus);

  const evaluations = parties.slice(0, t).map((party) => ({
    x: BigInt(party.id),
    // deno-lint-ignore no-non-null-assertion
    y: party.secretShare!,
  }));
  const f = lagrange.interpolate(evaluations);

  return f(0n);
}
