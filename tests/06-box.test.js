import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/box.random.js";

describe("nacl.box random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    var nonce = new Uint8Array(nacl.box.nonceLength);
    randomVectors.forEach(function (vec) {
      var pk1 = Uint8Array.fromBase64(vec[0]);
      var sk2 = Uint8Array.fromBase64(vec[1]);
      var msg = Uint8Array.fromBase64(vec[2]);
      var goodBox = Uint8Array.fromBase64(vec[3]);
      var box = nacl.box(msg, nonce, pk1, sk2);
      assert.equal(box.toBase64(), goodBox.toBase64());
      var openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
      assert.equal(openedBox.toBase64(), msg.toBase64());
    });
  });
});
