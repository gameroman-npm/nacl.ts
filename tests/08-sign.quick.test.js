import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import nacl from '../src/nacl-fast.js';

var enc = function(x) { return Buffer.from(x).toString('base64'); };

describe('nacl.sign.keyPair', function() {
  it('should generate valid key pair', function() {
    var keys = nacl.sign.keyPair();
    assert.ok(keys.secretKey && keys.secretKey.length === nacl.sign.secretKeyLength, 'has secret key');
    assert.ok(keys.publicKey && keys.publicKey.length === nacl.sign.publicKeyLength, 'has public key');
    assert.notEqual(enc(keys.secretKey), enc(keys.publicKey));
    var newKeys = nacl.sign.keyPair();
    assert.notEqual(enc(newKeys.secretKey), enc(keys.secretKey), 'two keys differ');
  });
});

describe('nacl.sign.keyPair.fromSecretKey', function() {
  it('should derive same key pair from secret key', function() {
    var k1 = nacl.sign.keyPair();
    var k2 = nacl.sign.keyPair.fromSecretKey(k1.secretKey);
    assert.equal(enc(k2.secretKey), enc(k1.secretKey));
    assert.equal(enc(k2.publicKey), enc(k1.publicKey));
  });
});

describe('nacl.sign.keyPair.fromSeed', function() {
  it('should generate consistent key pairs from seed', function() {
    var seed = nacl.randomBytes(nacl.sign.seedLength);
    var k1 = nacl.sign.keyPair.fromSeed(seed);
    var k2 = nacl.sign.keyPair.fromSeed(seed);
    assert.equal(k1.secretKey.length, nacl.sign.secretKeyLength);
    assert.equal(k1.publicKey.length, nacl.sign.publicKeyLength);
    assert.equal(k2.secretKey.length, nacl.sign.secretKeyLength);
    assert.equal(k2.publicKey.length, nacl.sign.publicKeyLength);
    assert.equal(enc(k2.secretKey), enc(k1.secretKey));
    assert.equal(enc(k2.publicKey), enc(k1.publicKey));
    var seed2 = nacl.randomBytes(nacl.sign.seedLength);
    var k3 = nacl.sign.keyPair.fromSeed(seed2);
    assert.equal(k3.secretKey.length, nacl.sign.secretKeyLength);
    assert.equal(k3.publicKey.length, nacl.sign.publicKeyLength);
    assert.notEqual(enc(k3.secretKey), enc(k1.secretKey));
    assert.notEqual(enc(k3.publicKey), enc(k1.publicKey));
    assert.throws(function() { nacl.sign.keyPair.fromSeed(seed2.subarray(0, 16)); }, Error);
  });
});

describe('nacl.sign and nacl.sign.open', function() {
  it('should sign and verify messages', function() {
    var k = nacl.sign.keyPair();
    var m = new Uint8Array(100);
    var i;
    for (i = 0; i < m.length; i++) m[i] = i & 0xff;
    var sm = nacl.sign(m, k.secretKey);
    assert.ok(sm.length > m.length, 'signed message length should be greater than message length');
    var om = nacl.sign.open(sm, k.publicKey);
    assert.deepEqual(om, m);
    assert.throws(function() { nacl.sign.open(sm, k.publicKey.subarray(1)); }, Error);
    var badPublicKey = new Uint8Array(k.publicKey.length);
    om = nacl.sign.open(sm, badPublicKey);
    assert.equal(om, null, 'opened message must be null when using wrong public key');
    for (i = 80; i < 90; i++) sm[i] = 0;
    om = nacl.sign.open(sm, k.publicKey);
    assert.equal(om, null, 'opened message must be null when opening bad signed message');
  });
});

describe('nacl.sign.detached and nacl.sign.detached.verify', function() {
  it('should create and verify detached signatures', function() {
    var k = nacl.sign.keyPair();
    var m = new Uint8Array(100);
    var i;
    for (i = 0; i < m.length; i++) m[i] = i & 0xff;
    var sig = nacl.sign.detached(m, k.secretKey);
    assert.ok(sig.length === nacl.sign.signatureLength, 'signature must have correct length');
    var result = nacl.sign.detached.verify(m, sig, k.publicKey);
    assert.ok(result, 'signature must be verified');
    assert.throws(function() { nacl.sign.detached.verify(m, sig, k.publicKey.subarray(1)); }, Error);
    assert.throws(function() { nacl.sign.detached.verify(m, sig.subarray(1), k.publicKey); }, Error);
    var badPublicKey = new Uint8Array(k.publicKey.length);
    result = nacl.sign.detached.verify(m, sig, badPublicKey);
    assert.equal(result, false, 'signature must not be verified with wrong public key');
    for (i = 0; i < 10; i++) sig[i] = 0;
    result = nacl.sign.detached.verify(m, sig, k.publicKey);
    assert.equal(result, false, 'bad signature must not be verified');
  });
});
