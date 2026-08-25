import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/secretbox.random.js";

describe("nacl.secretbox random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    randomVectors.forEach(function (vec) {
      var key = Uint8Array.fromBase64(vec[0]);
      var nonce = Uint8Array.fromBase64(vec[1]);
      var msg = Uint8Array.fromBase64(vec[2]);
      var goodBox = Uint8Array.fromBase64(vec[3]);
      var box = nacl.secretbox(msg, nonce, key);
      assert.ok(box, "box should be created");
      assert.equal(box.toBase64(), goodBox.toBase64());
      var openedBox = nacl.secretbox.open(goodBox, nonce, key);
      assert.ok(openedBox, "box should open");
      assert.equal(openedBox.toBase64(), msg.toBase64());
    });
  });
});
