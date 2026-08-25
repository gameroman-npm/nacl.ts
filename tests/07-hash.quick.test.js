import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import specVectors from "./data/hash.spec.js";

describe("nacl.hash length", function () {
  it("should return 64-byte hash for empty input", function () {
    assert.equal(nacl.hash(new Uint8Array(0)).length, 64);
  });

  it("should return 64-byte hash for 100-byte input", function () {
    assert.equal(nacl.hash(new Uint8Array(100)).length, 64);
  });
});

describe("nacl.hash exceptions for bad types", function () {
  it("should throw TypeError for string type", function () {
    assert.throws(function () {
      nacl.hash("string");
    }, TypeError);
  });

  it("should throw TypeError for array type", function () {
    assert.throws(function () {
      nacl.hash([1, 2, 3]);
    }, TypeError);
  });
});

describe("nacl.hash specified test vectors", function () {
  it("should match spec vectors", function () {
    specVectors.forEach(function (vec) {
      var goodHash = new Uint8Array(vec[0]);
      var msg = new Uint8Array(vec[1]);
      var hash = nacl.hash(msg);
      assert.equal(hash.toBase64(), goodHash.toBase64());
    });
  });
});
