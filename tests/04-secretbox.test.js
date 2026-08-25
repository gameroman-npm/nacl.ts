import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/secretbox.random.js";

describe("nacl.secretbox random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    randomVectors.forEach(function (vec) {
      const key = Uint8Array.fromBase64(vec[0]);
      const nonce = Uint8Array.fromBase64(vec[1]);
      const msg = Uint8Array.fromBase64(vec[2]);
      const goodBox = Uint8Array.fromBase64(vec[3]);
      const box = nacl.secretbox(msg, nonce, key);
      assert.ok(box, "box should be created");
      assert.equal(box.toBase64(), goodBox.toBase64());
      const openedBox = nacl.secretbox.open(goodBox, nonce, key);
      assert.ok(openedBox, "box should open");
      assert.equal(openedBox.toBase64(), msg.toBase64());
    });
  });
});
