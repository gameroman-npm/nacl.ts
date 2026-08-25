import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts";

describe("nacl.box.keyPair", function () {
  it("should generate valid key pair", function () {
    const keys = nacl.box.keyPair();
    assert.ok(
      keys.secretKey.length === nacl.box.secretKeyLength,
      "has secret key",
    );
    assert.ok(
      keys.publicKey.length === nacl.box.publicKeyLength,
      "has public key",
    );
    assert.notEqual(keys.secretKey.toBase64(), keys.publicKey.toBase64());
  });
});

describe("nacl.box.keyPair.fromSecretKey", function () {
  it("should derive same key pair from secret key", function () {
    const k1 = nacl.box.keyPair();
    const k2 = nacl.box.keyPair.fromSecretKey(k1.secretKey);
    assert.equal(k2.secretKey.toBase64(), k1.secretKey.toBase64());
    assert.equal(k2.publicKey.toBase64(), k1.publicKey.toBase64());
  });
});

describe("nacl.box and nacl.box.open", function () {
  it("should encrypt and decrypt message", function () {
    const clientKeys = nacl.box.keyPair();
    const serverKeys = nacl.box.keyPair();
    const nonce = new Uint8Array(nacl.box.nonceLength);
    for (let i = 0; i < nonce.length; i++) nonce[i] = (32 + i) & 0xff;
    const msg = new TextEncoder().encode("message to encrypt");
    const clientBox = nacl.box(
      msg,
      nonce,
      serverKeys.publicKey,
      clientKeys.secretKey,
    );
    const clientMsg = nacl.box.open(
      clientBox,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(
      new TextDecoder().decode(clientMsg),
      new TextDecoder().decode(msg),
    );
    const serverBox = nacl.box(
      msg,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(clientBox.toBase64(), serverBox.toBase64());
    const serverMsg = nacl.box.open(
      serverBox,
      nonce,
      serverKeys.publicKey,
      clientKeys.secretKey,
    );
    assert.equal(
      new TextDecoder().decode(serverMsg),
      new TextDecoder().decode(msg),
    );
  });
});

describe("nacl.box.open with invalid box", function () {
  it("should return null", function () {
    const clientKeys = nacl.box.keyPair();
    const serverKeys = nacl.box.keyPair();
    const nonce = new Uint8Array(nacl.box.nonceLength);
    assert.equal(
      nacl.box.open(
        new Uint8Array(0),
        nonce,
        serverKeys.publicKey,
        clientKeys.secretKey,
      ),
      null,
    );
    assert.equal(
      nacl.box.open(
        new Uint8Array(10),
        nonce,
        serverKeys.publicKey,
        clientKeys.secretKey,
      ),
      null,
    );
    assert.equal(
      nacl.box.open(
        new Uint8Array(100),
        nonce,
        serverKeys.publicKey,
        clientKeys.secretKey,
      ),
      null,
    );
  });
});

describe("nacl.box.open with invalid nonce", function () {
  it("should return null when nonce is wrong", function () {
    const clientKeys = nacl.box.keyPair();
    const serverKeys = nacl.box.keyPair();
    const nonce = new Uint8Array(nacl.box.nonceLength);
    for (let i = 0; i < nonce.length; i++) nonce[i] = i & 0xff;
    const msg = new TextEncoder().encode("message to encrypt");
    const box = nacl.box(
      msg,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(
      new TextDecoder().decode(
        nacl.box.open(box, nonce, serverKeys.publicKey, clientKeys.secretKey),
      ),
      new TextDecoder().decode(msg),
    );
    nonce[0] = 255;
    assert.equal(
      nacl.box.open(box, nonce, serverKeys.publicKey, clientKeys.secretKey),
      null,
    );
  });
});

describe("nacl.box.open with invalid keys", function () {
  it("should return null when keys are wrong", function () {
    const clientKeys = nacl.box.keyPair();
    const serverKeys = nacl.box.keyPair();
    const nonce = new Uint8Array(nacl.box.nonceLength);
    const msg = new TextEncoder().encode("message to encrypt");
    const box = nacl.box(
      msg,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(
      new TextDecoder().decode(
        nacl.box.open(box, nonce, serverKeys.publicKey, clientKeys.secretKey),
      ),
      new TextDecoder().decode(msg),
    );
    assert.equal(
      new TextDecoder().decode(
        nacl.box.open(box, nonce, clientKeys.publicKey, serverKeys.secretKey),
      ),
      new TextDecoder().decode(msg),
    );
    const badPublicKey = new Uint8Array(nacl.box.publicKeyLength);
    assert.equal(
      nacl.box.open(box, nonce, badPublicKey, clientKeys.secretKey),
      null,
    );
    const badSecretKey = new Uint8Array(nacl.box.secretKeyLength);
    assert.equal(
      nacl.box.open(box, nonce, serverKeys.publicKey, badSecretKey),
      null,
    );
  });
});
