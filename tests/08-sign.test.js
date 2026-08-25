import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import specVectors from "./data/sign.spec.js";

describe("nacl.sign and nacl.sign.open specified vectors", function () {
  it("should match spec vectors", { timeout: 15_000 }, function () {
    specVectors.forEach(function (vec) {
      const keys = nacl.sign.keyPair.fromSecretKey(
        Uint8Array.fromBase64(vec[0]),
      );
      const msg = Uint8Array.fromBase64(vec[1]);
      const goodSig = Uint8Array.fromBase64(vec[2]);

      const signedMsg = nacl.sign(msg, keys.secretKey);
      assert.equal(
        signedMsg.subarray(0, nacl.sign.signatureLength).toBase64(),
        goodSig.toBase64(),
        "signatures must be equal",
      );
      const openedMsg = nacl.sign.open(signedMsg, keys.publicKey);
      assert.equal(
        openedMsg.toBase64(),
        msg.toBase64(),
        "messages must be equal",
      );
    });
  });
});

describe("nacl.sign.detached and nacl.sign.detached.verify some specified vectors", function () {
  it("should match some spec vectors", function () {
    specVectors.forEach(function (vec, i) {
      if (i % 100 !== 0) return;

      const keys = nacl.sign.keyPair.fromSecretKey(
        Uint8Array.fromBase64(vec[0]),
      );
      const msg = Uint8Array.fromBase64(vec[1]);
      const goodSig = Uint8Array.fromBase64(vec[2]);

      const sig = nacl.sign.detached(msg, keys.secretKey);
      assert.equal(
        sig.toBase64(),
        goodSig.toBase64(),
        "signatures must be equal",
      );
      const result = nacl.sign.detached.verify(msg, sig, keys.publicKey);
      assert.ok(result, "signature must be verified");
    });
  });
});
