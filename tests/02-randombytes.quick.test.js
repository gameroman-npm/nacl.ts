import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

describe("nacl.randomBytes", function () {
  it("no collisions", function () {
    var set = {},
      s,
      i;
    for (i = 0; i < 10000; i++) {
      s = Buffer.from(nacl.randomBytes(32)).toString("base64");
      if (set[s]) {
        assert.fail("duplicate random sequence! " + s);
        return;
      }
      set[s] = true;
    }
  });
});
