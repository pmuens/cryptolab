import { Lagrange } from "../../lagrange-interpolation/main.ts";
import { Party } from "../../distributed-key-generation/main.ts";

export function recoverSecret<T extends Party>(
  parties: T[],
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
