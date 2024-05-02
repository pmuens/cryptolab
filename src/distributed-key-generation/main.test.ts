import { expect } from "$std/expect/mod.ts";
import { beforeAll, describe, it } from "$std/testing/bdd.ts";

import { DKG, Party } from "./main.ts";
import { mod } from "../shared/utils.ts";
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

    const dkg = await DKG.init(t, n, curve);
    await dkg.run();

    const [s, sPrime] = calculateSecrets(dkg.parties, t, curve.n);

    expect(sPrime).toBe(s);
  });

  it("should derive a key pair and be able to recover the private key if the threshold is exceeded", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = await DKG.init(t, n, curve);
    await dkg.run();

    const [s, sPrime] = calculateSecrets(dkg.parties, n, curve.n);

    expect(sPrime).toBe(s);
  });

  it("should derive a key pair and not be able to recover the private key if the threshold is not met", async () => {
    // 2 / 3 Scheme.
    const t = 2;
    const n = 3;

    const dkg = await DKG.init(t, n, curve);
    await dkg.run();

    const [s, sPrime] = calculateSecrets(dkg.parties, t - 1, curve.n);

    expect(sPrime).not.toBe(s);
  });
});

function calculateSecrets(
  parties: Party[],
  t: number,
  modulus: bigint,
): bigint[] {
  const lagrange = new Lagrange(modulus);

  const secret = parties.slice(0, t + 1).reduce(
    (accum, party) => mod(accum + party.polynomial.coefficients[0], modulus),
    0n,
  );

  const evaluations = parties.map((party) => ({
    x: BigInt(party.id),
    // deno-lint-ignore no-non-null-assertion
    y: party.secretShare!,
  }));
  const f = lagrange.interpolate(evaluations);
  const secretPrime = f(0n);

  return [secret, secretPrime];
}
