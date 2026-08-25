import assert from "node:assert/strict";
import { describe, it } from "node:test";

import nacl from "nacl.ts/fast";

var enc = function (x) {
  return Buffer.from(x).toString("base64");
};

describe("nacl.box.keyPair", function () {
  it("should generate valid key pair", function () {
    var keys = nacl.box.keyPair();
    assert.ok(
      keys.secretKey && keys.secretKey.length === nacl.box.secretKeyLength,
      "has secret key",
    );
    assert.ok(
      keys.publicKey && keys.publicKey.length === nacl.box.publicKeyLength,
      "has public key",
    );
    assert.notEqual(enc(keys.secretKey), enc(keys.publicKey));
  });
});

describe("nacl.box.keyPair.fromSecretKey", function () {
  it("should derive same key pair from secret key", function () {
    var k1 = nacl.box.keyPair();
    var k2 = nacl.box.keyPair.fromSecretKey(k1.secretKey);
    assert.equal(enc(k2.secretKey), enc(k1.secretKey));
    assert.equal(enc(k2.publicKey), enc(k1.publicKey));
  });
});

describe("nacl.box and nacl.box.open", function () {
  it("should encrypt and decrypt message", function () {
    var clientKeys = nacl.box.keyPair();
    var serverKeys = nacl.box.keyPair();
    var nonce = new Uint8Array(nacl.box.nonceLength);
    for (var i = 0; i < nonce.length; i++) nonce[i] = (32 + i) & 0xff;
    var msg = new TextEncoder().encode("message to encrypt");
    var clientBox = nacl.box(
      msg,
      nonce,
      serverKeys.publicKey,
      clientKeys.secretKey,
    );
    var clientMsg = nacl.box.open(
      clientBox,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(
      new TextDecoder().decode(clientMsg),
      new TextDecoder().decode(msg),
    );
    var serverBox = nacl.box(
      msg,
      nonce,
      clientKeys.publicKey,
      serverKeys.secretKey,
    );
    assert.equal(enc(clientBox), enc(serverBox));
    var serverMsg = nacl.box.open(
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
    var clientKeys = nacl.box.keyPair();
    var serverKeys = nacl.box.keyPair();
    var nonce = new Uint8Array(nacl.box.nonceLength);
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
    var clientKeys = nacl.box.keyPair();
    var serverKeys = nacl.box.keyPair();
    var nonce = new Uint8Array(nacl.box.nonceLength);
    for (var i = 0; i < nonce.length; i++) nonce[i] = i & 0xff;
    var msg = new TextEncoder().encode("message to encrypt");
    var box = nacl.box(msg, nonce, clientKeys.publicKey, serverKeys.secretKey);
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
    var clientKeys = nacl.box.keyPair();
    var serverKeys = nacl.box.keyPair();
    var nonce = new Uint8Array(nacl.box.nonceLength);
    var msg = new TextEncoder().encode("message to encrypt");
    var box = nacl.box(msg, nonce, clientKeys.publicKey, serverKeys.secretKey);
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
    var badPublicKey = new Uint8Array(nacl.box.publicKeyLength);
    assert.equal(
      nacl.box.open(box, nonce, badPublicKey, clientKeys.secretKey),
      null,
    );
    var badSecretKey = new Uint8Array(nacl.box.secretKeyLength);
    assert.equal(
      nacl.box.open(box, nonce, serverKeys.publicKey, badSecretKey),
      null,
    );
  });
});
