import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/box.random.js";

describe("nacl.box random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    const nonce = new Uint8Array(nacl.box.nonceLength);
    randomVectors.forEach(function (vec) {
      const pk1 = Uint8Array.fromBase64(vec[0]);
      const sk2 = Uint8Array.fromBase64(vec[1]);
      const msg = Uint8Array.fromBase64(vec[2]);
      const goodBox = Uint8Array.fromBase64(vec[3]);
      const box = nacl.box(msg, nonce, pk1, sk2);
      assert.equal(box.toBase64(), goodBox.toBase64());
      const openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
      assert.equal(openedBox.toBase64(), msg.toBase64());
    });
  });
});
