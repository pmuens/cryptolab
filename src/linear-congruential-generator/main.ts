// Adaption of Musl version.
//  See: https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
export class LCG {
  private a: bigint;
  private r: bigint;
  private c: bigint;
  private m: bigint;

  constructor(r: bigint) {
    this.a = 6_364_136_223_846_793_005n;
    this.r = r;
    this.c = 1n;
    this.m = BigInt(2 ** 64);
  }

  rand() {
    this.r = (this.a * this.r + this.c) % this.m;
    return this.r;
  }
}
