import { ECC } from "../shared/ecc/ecc.ts";
import { PublicKey, SharedSecret } from "../shared/ecc/types.ts";

export class ECDH extends ECC {
  deriveSecret(pk: PublicKey): SharedSecret {
    return pk.scalarMul(this.sk);
  }
}
