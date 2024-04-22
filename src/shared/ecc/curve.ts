export class Curve {
  name: string;
  p: bigint;
  a: bigint;
  b: bigint;
  gx: bigint;
  gy: bigint;
  n: bigint;
  h: bigint;

  constructor(
    name: string,
    p: bigint,
    a: bigint,
    b: bigint,
    gx: bigint,
    gy: bigint,
    n: bigint,
    h: bigint,
  ) {
    this.name = name;
    this.p = p;
    this.a = a;
    this.b = b;
    this.gx = gx;
    this.gy = gy;
    this.n = n;
    this.h = h;
  }
}

// See: https://en.bitcoin.it/wiki/Secp256k1
export class Secp256k1 extends Curve {
  constructor() {
    const name = "secp256k1";
    // Prime.
    const p = BigInt(
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
    // Curve coefficients.
    const a = 0n;
    const b = 7n;
    // Base point.
    const gx = BigInt(
      "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    const gy = BigInt(
      "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
    // Subgroup order.
    const n = BigInt(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    // Subgroup cofactor.
    const h = 1n;

    super(name, p, a, b, gx, gy, n, h);
  }
}
