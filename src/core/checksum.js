import { createHash, timingSafeEqual } from 'node:crypto';

import { ClaudeyError } from './errors.js';

const HEX_DIGEST = /^[a-fA-F0-9]{64}$/;
const SAFE_BASENAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function integrityError(message, assetName) {
  return new ClaudeyError('CHECKSUM_MISMATCH', message, {
    details: assetName ? { assetName } : {}
  });
}

function assertBareAssetName(assetName) {
  if (
    typeof assetName !== 'string' ||
    !SAFE_BASENAME.test(assetName) ||
    assetName === '.' ||
    assetName === '..' ||
    assetName.startsWith('-') ||
    assetName.includes('..') ||
    /[\\/:]/.test(assetName)
  ) {
    throw integrityError('The release asset filename is unsafe.');
  }
  return assetName;
}

function normalizeDigest(value, assetName) {
  if (typeof value !== 'string' || !HEX_DIGEST.test(value)) {
    throw integrityError('The release checksum digest is invalid.', assetName);
  }
  return value.toLowerCase();
}

function parseRecord(line, requestedAssetName) {
  const match = /^([a-fA-F0-9]{64})[ \t]+\*?([^ \t]+)$/.exec(line);
  if (!match) throw integrityError('The release checksum record is malformed.', requestedAssetName);
  const [, digest, assetName] = match;
  assertBareAssetName(assetName);
  return { digest: normalizeDigest(digest, requestedAssetName), assetName };
}

function normalizeLogicalLine(rawLine, requestedAssetName) {
  const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
  if (line.includes('\r') || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(line)) {
    throw integrityError('The release checksum artifact contains a control character.', requestedAssetName);
  }
  return line;
}

/**
 * Parse a strict SHA-256 checksum artifact and return the one digest belonging
 * to the exact selected archive basename.  Other safe asset rows are allowed;
 * they cannot satisfy the selected filename lookup.
 */
export function parseChecksumManifest(text, requestedAssetName) {
  const expectedName = assertBareAssetName(requestedAssetName);
  if (typeof text !== 'string') throw integrityError('The release checksum artifact is not text.', expectedName);

  let selected;
  for (const rawLine of text.split('\n')) {
    const line = normalizeLogicalLine(rawLine, expectedName);
    if (line === '' || line.startsWith('#')) continue;
    const record = parseRecord(line, expectedName);
    if (record.assetName !== expectedName) continue;
    if (selected !== undefined) throw integrityError('The release checksum artifact is ambiguous.', expectedName);
    selected = record.digest;
  }
  if (selected === undefined) throw integrityError('The release checksum artifact has no digest for the selected archive.', expectedName);
  return selected;
}

function asBuffer(value, assetName) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw integrityError('The release archive bytes are invalid.', assetName);
}

export function createSha256Verifier(expectedDigest, assetName) {
  const expected = normalizeDigest(expectedDigest, assertBareAssetName(assetName));
  const hash = createHash('sha256');
  let bytes = 0;
  let finalized = false;

  return Object.freeze({
    update(value) {
      if (finalized) throw integrityError('The release checksum verifier is already finalized.', assetName);
      const chunk = asBuffer(value, assetName);
      bytes += chunk.length;
      hash.update(chunk);
      return chunk;
    },
    finish() {
      if (finalized) throw integrityError('The release checksum verifier is already finalized.', assetName);
      finalized = true;
      const actual = hash.digest('hex');
      const matches = timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
      if (!matches) throw integrityError('The release archive checksum did not match.', assetName);
      return Object.freeze({ assetName, bytes, sha256: actual });
    }
  });
}

export function verifySha256(value, expectedDigest, assetName) {
  const verifier = createSha256Verifier(expectedDigest, assetName);
  verifier.update(value);
  return verifier.finish();
}
