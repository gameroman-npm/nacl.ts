declare interface BoxKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

declare interface SignKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

declare interface Secretbox {
  (msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null;
  readonly keyLength: number;
  readonly nonceLength: number;
  readonly overheadLength: number;
}

declare interface ScalarMult {
  (n: Uint8Array, p: Uint8Array): Uint8Array;
  base(n: Uint8Array): Uint8Array;
  readonly scalarLength: number;
  readonly groupElementLength: number;
}

declare namespace BoxProps {
  interface Open {
    (msg: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array | null;
    after(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null;
  }

  interface KeyPair {
    (): BoxKeyPair;
    fromSecretKey(secretKey: Uint8Array): BoxKeyPair;
  }
}

declare interface Box {
  (msg: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  before(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  after(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  open: BoxProps.Open;
  keyPair: BoxProps.KeyPair;
  readonly publicKeyLength: number;
  readonly secretKeyLength: number;
  readonly sharedKeyLength: number;
  readonly nonceLength: number;
  readonly overheadLength: number;
}

declare namespace SignProps {
  interface Detached {
    (msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
    verify(msg: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean;
  }

  interface KeyPair {
    (): SignKeyPair;
    fromSecretKey(secretKey: Uint8Array): SignKeyPair;
    fromSeed(secretKey: Uint8Array): SignKeyPair;
  }
}

declare interface Sign {
  (msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
  open(signedMsg: Uint8Array, publicKey: Uint8Array): Uint8Array | null;
  detached: SignProps.Detached;
  keyPair: SignProps.KeyPair;
  readonly publicKeyLength: number;
  readonly secretKeyLength: number;
  readonly seedLength: number;
  readonly signatureLength: number;
}

declare interface Hash {
  (msg: Uint8Array): Uint8Array;
  readonly hashLength: number;
}

declare interface Nacl {
  randomBytes(n: number): Uint8Array;
  secretbox: Secretbox;
  scalarMult: ScalarMult;
  box: Box;
  sign: Sign;
  hash: Hash;
  verify(x: Uint8Array, y: Uint8Array): boolean;
  setPRNG(fn: (x: Uint8Array, n: number) => void): void;
}

declare const nacl: Nacl;
export default nacl;

export type { BoxKeyPair, SignKeyPair, Secretbox, ScalarMult, Box, Sign, Hash, Nacl };
