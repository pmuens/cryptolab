import { ECC } from "./ecc.ts";
import { PublicKey, SharedSecret } from "./types.ts";

export class ECDH extends ECC {
  deriveSecret(pk: PublicKey): SharedSecret {
    return pk.scalarMul(this.sk);
  }
}
