import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

import specVectors from "./data/hash.spec.js";

describe("nacl.hash length", function () {
  it("should return 64-byte hash for empty input", async function () {
    const hash = await nacl.hash(new Uint8Array(0));
    assert.equal(hash.length, 64);
  });

  it("should return 64-byte hash for 100-byte input", async function () {
    const hash = await nacl.hash(new Uint8Array(100));
    assert.equal(hash.length, 64);
  });
});

describe("nacl.hash exceptions for bad types", function () {
  it("should throw TypeError for string type", async function () {
    await assert.rejects(nacl.hash("string"), TypeError);
  });

  it("should throw TypeError for array type", async function () {
    await assert.rejects(nacl.hash([1, 2, 3]), TypeError);
  });
});

describe("nacl.hash specified test vectors", function () {
  it("should match spec vectors", async function () {
    for (const vec of specVectors) {
      const goodHash = new Uint8Array(vec[0]);
      const msg = new Uint8Array(vec[1]);
      const hash = await nacl.hash(msg);
      assert.equal(hash.toBase64(), goodHash.toBase64());
    }
  });
});
