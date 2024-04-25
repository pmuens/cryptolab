import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";
import { int2BytesBe } from "./utils.ts";

import { concat, egcd, inverseOf, toBinary } from "./utils.ts";

describe("Utils", () => {
  it("toBinary", () => {
    const number = 151n;
    const result = [];

    for (const bit of toBinary(number)) {
      result.push(bit);
    }

    expect(result).toEqual([1n, 1n, 1n, 0n, 1n, 0n, 0n, 1n]);
  });

  it("egcd", () => {
    const a = 1432n;
    const b = 123211n;
    const [gcd, x, y] = egcd(a, b);

    expect(gcd).toBe(1n);
    expect(x).toBe(-22973n);
    expect(y).toBe(267n);
  });

  it("inverseOf", () => {
    const a = 4n;
    const b = 13n;
    const inverse = inverseOf(a, b);

    expect(inverse).toBe(10n);
  });

  describe("concat", () => {
    it("should support a single bigint", () => {
      const items = [42n];
      // deno-fmt-ignore
      const data = new Uint8Array([
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,  42,
      ]);

      const result = concat(items[0]);

      expect(result).toEqual(data);
    });

    it("should support multiple bigints", () => {
      const items = [
        42n,
        42298390733849302668478672888816430860653355038368712747919352596078205083908n,
      ];
      // deno-fmt-ignore
      const data = new Uint8Array([
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,  42, 93, 132,  10, 110,
        189, 226, 115, 254, 38, 100, 151,  54,  1, 127, 234, 112,
        55, 173, 133, 117, 44,  49,  67, 170,  3,  23, 193, 123,
        35, 120,  33,   4
      ]);

      const result = concat(...items);

      expect(result).toEqual(data);
    });

    it("should support a single byte array", () => {
      const items = [
        new Uint8Array([
          42,
        ]),
      ];
      const data = new Uint8Array([
        42,
      ]);

      const result = concat(items[0]);

      expect(result).toEqual(data);
    });

    it("should support multiple byte arrays", () => {
      const items = [
        new Uint8Array([
          42,
        ]),
        // deno-fmt-ignore
        new Uint8Array([
          0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
          0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
          0,   0,   0,   0,  0,   0,   0,  42,
        ]),
      ];
      // deno-fmt-ignore
      const data = new Uint8Array([
        42,
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,  0,   0,   0,  42,
      ]);

      const result = concat(...items);

      expect(result).toEqual(data);
    });

    it("should support a mix of bigints and byte arrays (explicit)", () => {
      const items = [
        40583080589636752393613366097361022586072122530467531283715425369821050782854n,
        70034521844012561416150622694397913020875807313088650183979905443515724804916n,
        67758156425139007158359008498347018679363195325768020029039332487067615985897n,
        51657421956789903834116502718639273448195675835105177973555795136371427055516n,
        // deno-fmt-ignore
        new Uint8Array([
          0, 1, 2, 3, 4,
          5, 6, 7, 8, 9
        ]),
      ];
      // deno-fmt-ignore
      const data = new Uint8Array([
        // Item #1.
        89, 185,  53, 169,  94, 134, 122,  33,
        243, 177, 154,  90, 146, 156, 178, 195,
        228,   9,  42, 125,  44, 135, 145,   6,
        74,  90, 128,  87, 132,  19,  68, 134,
        // Item #2.
        154, 214,  34, 119, 215, 183,  58, 214,
        85,  54,  61, 254,  26,  85, 234, 171,
          9, 203, 244,  81,  84, 215,  16, 170,
        72, 229, 171, 120, 160, 193,  51,  52,
        // Item #3.
        149, 205, 193, 233, 182, 178, 112,  74,
          8, 190, 108, 193,  33, 205, 205, 128,
        184, 177, 201, 169,   1, 113,  42,  95,
        83, 202, 189, 124, 130,   5, 128, 233,
        // Item #4.
        114,  53,  16, 144, 129, 255, 140,
        152, 210,  93, 127,  89, 102, 173,
        180, 199,  66, 188, 214,  18, 231,
        106, 248, 185, 253, 110, 217, 192,
        107, 211,  23, 156,
        // Item #5.
        0, 1, 2, 3, 4,
        5, 6, 7, 8, 9,
      ])

      const result = concat(...items);

      expect(result).toEqual(data);
    });

    it("should support a mix of bigints and byte arrays (simplified)", () => {
      const items = [
        40583080589636752393613366097361022586072122530467531283715425369821050782854n,
        70034521844012561416150622694397913020875807313088650183979905443515724804916n,
        67758156425139007158359008498347018679363195325768020029039332487067615985897n,
        51657421956789903834116502718639273448195675835105177973555795136371427055516n,
        // deno-fmt-ignore
        new Uint8Array([
          0, 1, 2, 3, 4,
          5, 6, 7, 8, 9
        ]),
      ];
      // deno-fmt-ignore
      const data = new Uint8Array([
        ...int2BytesBe(items[0] as bigint),
        ...int2BytesBe(items[1] as bigint),
        ...int2BytesBe(items[2] as bigint),
        ...int2BytesBe(items[3] as bigint),
        0, 1, 2, 3, 4,
        5, 6, 7, 8, 9,
      ])

      const result = concat(...items);

      expect(result).toEqual(data);
    });
  });
});
