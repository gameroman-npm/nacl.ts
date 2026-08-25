import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/scalarmult.random.js";

var enc = function (x) {
  return Buffer.from(x).toString("base64");
};
var dec = function (x) {
  return Buffer.from(x, "base64");
};

describe("nacl.scalarMult.base", function () {
  it("should compute correct base point multiplication", function () {
    var golden = new Uint8Array([
      0x89, 0x16, 0x1f, 0xde, 0x88, 0x7b, 0x2b, 0x53, 0xde, 0x54, 0x9a, 0xf4,
      0x83, 0x94, 0x01, 0x06, 0xec, 0xc1, 0x14, 0xd6, 0x98, 0x2d, 0xaa, 0x98,
      0x25, 0x6d, 0xe2, 0x3b, 0xdf, 0x77, 0x66, 0x1a,
    ]);
    var input = new Uint8Array([
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0,
    ]);
    for (var i = 0; i < 200; i++) {
      input = nacl.scalarMult.base(input);
    }
    assert.equal(enc(input), enc(golden));
  });
});

describe("nacl.scalarMult and nacl.scalarMult.base random test vectors", function () {
  it("should match random test vectors", function () {
    randomVectors.forEach(function (vec) {
      var pk1 = dec(vec[0]);
      var sk1 = dec(vec[1]);
      var pk2 = dec(vec[2]);
      var sk2 = dec(vec[3]);
      var out = dec(vec[4]);

      var jpk1 = nacl.scalarMult.base(sk1);
      assert.equal(enc(jpk1), enc(pk1));
      var jpk2 = nacl.scalarMult.base(sk2);
      assert.equal(enc(jpk2), enc(pk2));
      var jout1 = nacl.scalarMult(sk1, pk2);
      assert.equal(enc(jout1), enc(out));
      var jout2 = nacl.scalarMult(sk2, pk1);
      assert.equal(enc(jout2), enc(out));
    });
  });
});
