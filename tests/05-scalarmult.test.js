import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/scalarmult.random.js";

describe("nacl.scalarMult.base", function () {
  it("should compute correct base point multiplication", function () {
    const golden = new Uint8Array([
      0x89, 0x16, 0x1f, 0xde, 0x88, 0x7b, 0x2b, 0x53, 0xde, 0x54, 0x9a, 0xf4,
      0x83, 0x94, 0x01, 0x06, 0xec, 0xc1, 0x14, 0xd6, 0x98, 0x2d, 0xaa, 0x98,
      0x25, 0x6d, 0xe2, 0x3b, 0xdf, 0x77, 0x66, 0x1a,
    ]);
    let input = new Uint8Array([
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0,
    ]);
    for (let i = 0; i < 200; i++) {
      input = nacl.scalarMult.base(input);
    }
    assert.equal(input.toBase64(), golden.toBase64());
  });
});

describe("nacl.scalarMult and nacl.scalarMult.base random test vectors", function () {
  it("should match random test vectors", function () {
    randomVectors.forEach(function (vec) {
      const pk1 = Uint8Array.fromBase64(vec[0]);
      const sk1 = Uint8Array.fromBase64(vec[1]);
      const pk2 = Uint8Array.fromBase64(vec[2]);
      const sk2 = Uint8Array.fromBase64(vec[3]);
      const out = Uint8Array.fromBase64(vec[4]);

      const jpk1 = nacl.scalarMult.base(sk1);
      assert.equal(jpk1.toBase64(), pk1.toBase64());
      const jpk2 = nacl.scalarMult.base(sk2);
      assert.equal(jpk2.toBase64(), pk2.toBase64());
      const jout1 = nacl.scalarMult(sk1, pk2);
      assert.equal(jout1.toBase64(), out.toBase64());
      const jout2 = nacl.scalarMult(sk2, pk1);
      assert.equal(jout2.toBase64(), out.toBase64());
    });
  });
});
