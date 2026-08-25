import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'nacl.ts/fast';

var enc = function(x) { return Buffer.from(x).toString('base64'); };
var dec = function(x) { return Buffer.from(x, 'base64'); };

describe('nacl.secretbox and nacl.secretbox.open', function() {
  it('should encrypt and decrypt message', function() {
    var key = new Uint8Array(nacl.secretbox.keyLength);
    var nonce = new Uint8Array(nacl.secretbox.nonceLength);
    var i;
    for (i = 0; i < key.length; i++) key[i] = i & 0xff;
    for (i = 0; i < nonce.length; i++) nonce[i] = (32+i) & 0xff;
    var msg = new TextEncoder().encode('message to encrypt');
    var box = nacl.secretbox(msg, nonce, key);
    var openedMsg = nacl.secretbox.open(box, nonce, key);
    assert.equal(new TextDecoder().decode(openedMsg), new TextDecoder().decode(msg), 'opened messages should be equal');
  });
});

describe('nacl.secretbox.open with invalid box', function() {
  it('should return null', function() {
    var key = new Uint8Array(nacl.secretbox.keyLength);
    var nonce = new Uint8Array(nacl.secretbox.nonceLength);
    assert.equal(nacl.secretbox.open(new Uint8Array(0), nonce, key), null);
    assert.equal(nacl.secretbox.open(new Uint8Array(10), nonce, key), null);
    assert.equal(nacl.secretbox.open(new Uint8Array(100), nonce, key), null);
  });
});

describe('nacl.secretbox.open with invalid nonce', function() {
  it('should return null when nonce is wrong', function() {
    var key = new Uint8Array(nacl.secretbox.keyLength);
    var nonce = new Uint8Array(nacl.secretbox.nonceLength);
    for (var i = 0; i < nonce.length; i++) nonce[i] = i & 0xff;
    var msg = new TextEncoder().encode('message to encrypt');
    var box = nacl.secretbox(msg, nonce, key);
    assert.equal(new TextDecoder().decode(nacl.secretbox.open(box, nonce, key)),
            new TextDecoder().decode(msg));
    nonce[0] = 255;
    assert.equal(nacl.secretbox.open(box, nonce, key), null);
  });
});

describe('nacl.secretbox.open with invalid key', function() {
  it('should return null when key is wrong', function() {
    var key = new Uint8Array(nacl.secretbox.keyLength);
    for (var i = 0; i < key.length; i++) key[i] = i & 0xff;
    var nonce = new Uint8Array(nacl.secretbox.nonceLength);
    var msg = new TextEncoder().encode('message to encrypt');
    var box = nacl.secretbox(msg, nonce, key);
    assert.equal(new TextDecoder().decode(nacl.secretbox.open(box, nonce, key)),
            new TextDecoder().decode(msg));
    key[0] = 255;
    assert.equal(nacl.secretbox.open(box, nonce, key), null);
  });
});

describe('nacl.secretbox with message lengths of 0 to 1024', function() {
  it('should handle all message lengths', function() {
    var key = new Uint8Array(nacl.secretbox.keyLength);
    var i;
    for (i = 0; i < key.length; i++) key[i] = i & 0xff;
    var nonce = new Uint8Array(nacl.secretbox.nonceLength);
    var fullMsg = new Uint8Array(1024);
    for (i = 0; i < fullMsg.length; i++) fullMsg[i] = i & 0xff;
    for (i = 0; i < fullMsg.length; i++) {
      var msg = fullMsg.subarray(0, i);
      var box = nacl.secretbox(msg, nonce, key);
      var unbox = nacl.secretbox.open(box, nonce, key);
      assert.equal(enc(msg), enc(unbox));
    }
  });
});
