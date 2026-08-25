import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import nacl from '../src/nacl-fast.js';

var nonce = new Uint8Array(nacl.secretbox.nonceLength);
var key = new Uint8Array(nacl.secretbox.keyLength);
var msg = new Uint8Array(10);

var arr = [1,2,3];

describe('input type check', function() {
  it('throws TypeError for secretbox with bad types', function() {
    assert.throws(function() { nacl.secretbox(arr, nonce, key); }, TypeError);
    assert.throws(function() { nacl.secretbox(msg, arr, key); }, TypeError);
    assert.throws(function() { nacl.secretbox(msg, nonce, arr); }, TypeError);

    assert.throws(function() { nacl.secretbox.open(arr, nonce, key); }, TypeError);
    assert.throws(function() { nacl.secretbox.open(msg, arr, key); }, TypeError);
    assert.throws(function() { nacl.secretbox.open(msg, nonce, arr); }, TypeError);
  });

  it('throws TypeError for scalarMult with bad types', function() {
    assert.throws(function() { nacl.scalarMult(arr, key); }, TypeError);
    assert.throws(function() { nacl.scalarMult(key, arr); }, TypeError);
    assert.throws(function() { nacl.scalarMult.base(arr); }, TypeError);
  });

  it('throws TypeError for box with bad types', function() {
    assert.throws(function() { nacl.box(arr, nonce, key, key); }, TypeError);
    assert.throws(function() { nacl.box(msg, arr, key, key); }, TypeError);
    assert.throws(function() { nacl.box(msg, nonce, arr, key); }, TypeError);
    assert.throws(function() { nacl.box(msg, nonce, key, arr); }, TypeError);

    assert.throws(function() { nacl.box.open(arr, nonce, key, key); }, TypeError);
    assert.throws(function() { nacl.box.open(msg, arr, key, key); }, TypeError);
    assert.throws(function() { nacl.box.open(msg, nonce, arr, key); }, TypeError);
    assert.throws(function() { nacl.box.open(msg, nonce, key, arr); }, TypeError);

    assert.throws(function() { nacl.box.before(arr, key); }, TypeError);
    assert.throws(function() { nacl.box.before(key, arr); }, TypeError);

    assert.throws(function() { nacl.box.after(arr, nonce, key); }, TypeError);
    assert.throws(function() { nacl.box.after(msg, arr, key); }, TypeError);
    assert.throws(function() { nacl.box.after(msg, nonce, arr); }, TypeError);

    assert.throws(function() { nacl.box.open.after(arr, nonce, key); }, TypeError);
    assert.throws(function() { nacl.box.open.after(msg, arr, key); }, TypeError);
    assert.throws(function() { nacl.box.open.after(msg, nonce, arr); }, TypeError);

    assert.throws(function() { nacl.box.keyPair.fromSecretKey(arr); }, TypeError);
  });

  it('throws TypeError for sign with bad types', function() {
    assert.throws(function() { nacl.sign(arr, key); }, TypeError);
    assert.throws(function() { nacl.sign(msg, arr); }, TypeError);

    assert.throws(function() { nacl.sign.open(arr, key); }, TypeError);
    assert.throws(function() { nacl.sign.open(msg, arr); }, TypeError);

    assert.throws(function() { nacl.sign.detached(arr, key); }, TypeError);
    assert.throws(function() { nacl.sign.detached(msg, arr); }, TypeError);

    assert.throws(function() { nacl.sign.detached.verify(arr, key, key); }, TypeError);
    assert.throws(function() { nacl.sign.detached.verify(msg, arr, key); }, TypeError);
    assert.throws(function() { nacl.sign.detached.verify(msg, key, arr); }, TypeError);

    assert.throws(function() { nacl.sign.keyPair.fromSecretKey(arr); }, TypeError);
    assert.throws(function() { nacl.sign.keyPair.fromSeed(arr); }, TypeError);
  });

  it('throws TypeError for hash with bad types', function() {
    assert.throws(function() { nacl.hash(arr); }, TypeError);
  });

  it('throws TypeError for verify with bad types', function() {
    assert.throws(function() { nacl.verify(arr, msg); }, TypeError);
    assert.throws(function() { nacl.verify(msg, arr); }, TypeError);
  });
});
