import { expect } from "$std/expect/mod.ts";
import { describe, it } from "$std/testing/bdd.ts";

import Person, { sayHello } from "./main.ts";

describe("sayHello", () => {
  it("should return a greeting", () => {
    const grace: Person = {
      lastName: "Hopper",
      firstName: "Grace",
    };

    const result = sayHello(grace);

    expect(result).toBe("Hello, Grace!");
  });
});
