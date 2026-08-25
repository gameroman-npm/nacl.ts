import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import randomVectors from "./data/box.random.js";

var enc = function (x) {
  return Buffer.from(x).toString("base64");
};
var dec = function (x) {
  return Buffer.from(x, "base64");
};

describe("nacl.box random test vectors", function () {
  it("should encrypt and decrypt correctly", function () {
    var nonce = new Uint8Array(nacl.box.nonceLength);
    randomVectors.forEach(function (vec) {
      var pk1 = dec(vec[0]);
      var sk2 = dec(vec[1]);
      var msg = dec(vec[2]);
      var goodBox = dec(vec[3]);
      var box = nacl.box(msg, nonce, pk1, sk2);
      assert.equal(enc(box), enc(goodBox));
      var openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
      assert.equal(enc(openedBox), enc(msg));
    });
  });
});
