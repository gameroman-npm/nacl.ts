import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import specVectors from "./data/sign.spec.js";

var enc = function (x) {
  return Buffer.from(x).toString("base64");
};
var dec = function (x) {
  return Buffer.from(x, "base64");
};

describe("nacl.sign and nacl.sign.open specified vectors", function () {
  it("should match spec vectors", { timeout: 10_000 }, function () {
    specVectors.forEach(function (vec) {
      var keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
      var msg = dec(vec[1]);
      var goodSig = dec(vec[2]);

      var signedMsg = nacl.sign(msg, keys.secretKey);
      assert.equal(
        enc(signedMsg.subarray(0, nacl.sign.signatureLength)),
        enc(goodSig),
        "signatures must be equal",
      );
      var openedMsg = nacl.sign.open(signedMsg, keys.publicKey);
      assert.equal(enc(openedMsg), enc(msg), "messages must be equal");
    });
  });
});

describe("nacl.sign.detached and nacl.sign.detached.verify some specified vectors", function () {
  it("should match some spec vectors", function () {
    specVectors.forEach(function (vec, i) {
      if (i % 100 !== 0) return;

      var keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
      var msg = dec(vec[1]);
      var goodSig = dec(vec[2]);

      var sig = nacl.sign.detached(msg, keys.secretKey);
      assert.equal(enc(sig), enc(goodSig), "signatures must be equal");
      var result = nacl.sign.detached.verify(msg, sig, keys.publicKey);
      assert.ok(result, "signature must be verified");
    });
  });
});
