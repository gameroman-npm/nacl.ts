import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import nacl from '../src/nacl-fast.js';
import randomVectors from './data/hash.random.js';

var enc = function(x) { return Buffer.from(x).toString('base64'); };
var dec = function(x) { return Buffer.from(x, 'base64'); };

describe('nacl.hash random test vectors', function() {
  it('should hash correctly', function() {
    randomVectors.forEach(function(vec) {
      var msg = dec(vec[0]);
      var goodHash = dec(vec[1]);
      var hash = nacl.hash(msg);
      assert.equal(enc(hash), enc(goodHash));
    });
  });
});
