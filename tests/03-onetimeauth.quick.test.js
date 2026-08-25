import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import specVectors from "./data/onetimeauth.spec.js";

describe("nacl.lowlevel.crypto_onetimeauth specified vectors", function () {
  it("should match spec vectors", function () {
    var out = new Uint8Array(16);
    specVectors.forEach(function (v) {
      nacl.lowlevel.crypto_onetimeauth(out, 0, v.m, 0, v.m.length, v.k);
      assert.equal(out.toBase64(), v.out.toBase64());
    });
  });
});
