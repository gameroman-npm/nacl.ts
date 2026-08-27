import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/hash.random.js";

describe("nacl.hash random test vectors", function () {
  it("should hash correctly", async function () {
    for (const vec of randomVectors) {
      const msg = Uint8Array.fromBase64(vec[0]);
      const goodHash = Uint8Array.fromBase64(vec[1]);
      const hash = await nacl.hash(msg);
      assert.equal(hash.toBase64(), goodHash.toBase64());
    }
  });
});
