import { describe, it, expect } from 'vitest';
import { sha256Hex } from '../../../src/evidence/hash';

describe('sha256Hex', () => {
  it('hashes the empty string to the known vector', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('hashes "abc" to the known vector', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('gives the same digest for a string and its utf-8 buffer', () => {
    expect(sha256Hex(Buffer.from('abc', 'utf8'))).toBe(sha256Hex('abc'));
  });

  it('returns 64 lowercase hex characters', () => {
    expect(sha256Hex('tessera')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashes raw bytes that are not valid utf-8', () => {
    expect(sha256Hex(Buffer.from([0xff, 0xfe, 0x00]))).not.toBe(sha256Hex(Buffer.from([0xff, 0xfe, 0x01])));
  });
});
