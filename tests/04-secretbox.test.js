import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/secretbox.random.js";

var enc = function (x) {
  return Buffer.from(x).toString("base64");
};
var dec = function (x) {
  return Buffer.from(x, "base64");
};

describe("nacl.secretbox random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    randomVectors.forEach(function (vec) {
      var key = dec(vec[0]);
      var nonce = dec(vec[1]);
      var msg = dec(vec[2]);
      var goodBox = dec(vec[3]);
      var box = nacl.secretbox(msg, nonce, key);
      assert.ok(box, "box should be created");
      assert.equal(enc(box), enc(goodBox));
      var openedBox = nacl.secretbox.open(goodBox, nonce, key);
      assert.ok(openedBox, "box should open");
      assert.equal(enc(openedBox), enc(msg));
    });
  });
});
