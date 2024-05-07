import { expect } from "$std/expect/mod.ts";
import { beforeAll, describe, it } from "$std/testing/bdd.ts";

import { DKG } from "./main.ts";
import { Secp256k1 } from "../shared/ecc/curve.ts";
import { recoverSecret } from "../shared/testing/utils.ts";

describe("Proactive Secret Sharing", () => {
  let curve: Secp256k1;

  beforeAll(() => {
    curve = new Secp256k1();
  });

  it("should refresh secret shares while preserving the private- and public key", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = new DKG(t, n, curve);
    const pk = await dkg.keygen();

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
