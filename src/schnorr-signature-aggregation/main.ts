import { Point } from "../shared/ecc/point.ts";
import { concat, mod } from "../shared/utils.ts";
import { PublicKey } from "../shared/ecc/types.ts";
import { SchnorrSignature, Signature } from "../schnorr-signature/main.ts";

export class SchnorrSignatureAggregation extends SchnorrSignature {
  signers: Signer[];

  // Use `init` as a "constructor" to allow for `async` functions.
  static async init(signers: Signer[]): Promise<SchnorrSignatureAggregation> {
    const verifier = new SchnorrSignature();

    // Verify KOSK to prevent Rogue-Key Attacks.
    for await (const signer of signers) {
      const isValid = await verifier.verify(
        signer.schnorr.pk,
        pk2Bytes(signer.schnorr.pk),
        signer.kosk,
      );
      if (!isValid) {
        throw new Error("Error validating signature over public key...");
      }
    }

    return new SchnorrSignatureAggregation(signers);
  }

  async sign(
    message: Uint8Array,
  ): Promise<Signature> {
    const R = this.R;
    const pk = this.pk;
    const n = this.curve.n;

    const c = await this.createChallenge(pk, R, message);

    const es: bigint[] = [];
    for (const signer of this.signers) {
      const e = mod(signer.schnorr.r + mod(c * signer.schnorr.sk, n), n);
      es.push(e);
    }

    const e = es.reduce((accum, e) => {
      return mod(accum + e, n);
    }, 0n);

    return {
      R,
      e,
    };
  }

  private constructor(signers: Signer[]) {
    super();

    let R = Point.infinity(this.curve);
    let pk = Point.infinity(this.curve);

    for (const signer of signers) {
      R = R.add(signer.schnorr.R);
      pk = pk.add(signer.schnorr.pk);
    }

    this.R = R;
    this.pk = pk;
    this.signers = signers;
  }
}

export function pk2Bytes(pk: PublicKey): Uint8Array {
  return concat(pk.x, pk.y);
}

type Signer = {
  kosk: Signature;
  schnorr: SchnorrSignature;
};
