import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'nacl.ts/fast';

describe('nacl.verify', function() {
  it('equal arrays of length 1 should verify', function() {
    assert.ok(nacl.verify(new Uint8Array(1), new Uint8Array(1)));
  });

  it('equal arrays of length 1000 should verify', function() {
    assert.ok(nacl.verify(new Uint8Array(1000), new Uint8Array(1000)));
  });

  it('equal arrays should verify', function() {
    var a = new Uint8Array(764), b = new Uint8Array(764);
    for (var i = 0; i < a.length; i++) a[i] = b[i] = i & 0xff;
    assert.ok(nacl.verify(a, b));
  });

  it('same arrays should verify', function() {
    var a = new Uint8Array(764), b = new Uint8Array(764);
    for (var i = 0; i < a.length; i++) a[i] = b[i] = i & 0xff;
    assert.ok(nacl.verify(a, a));
  });

  it('different arrays don\'t verify', function() {
    var a = new Uint8Array(764), b = new Uint8Array(764);
    for (var i = 0; i < a.length; i++) a[i] = b[i] = i & 0xff;
    b[0] = 255;
    assert.ok(!nacl.verify(a, b));
  });

  it('arrays of different lengths should not verify', function() {
    assert.ok(!nacl.verify(new Uint8Array(1), new Uint8Array(10)));
  });

  it('zero-length arrays should not verify', function() {
    assert.ok(!nacl.verify(new Uint8Array(0), new Uint8Array(0)));
  });
});
