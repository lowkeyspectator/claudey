import crypto from 'node:crypto';
import path from 'node:path';

import { ClaudexError } from '../core/errors.js';
import { deriveApprovalKey } from '../core/manifest.js';
import { isSecret, normalizePromptForApproval } from '../core/secrets.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ID = /^[A-Za-z0-9_-]{43}$/u;
const HEX = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const TTL_MS = 300_000;

function fail(code = 'SAFETY_REFUSAL') {
  const messages = {
    SAFETY_REFUSAL: 'The Cursor approval could not be handled safely.',
    APPROVAL_INVALID: 'The Cursor approval is invalid, expired, declined, or already consumed.',
    INTERACTION_REQUIRED: 'Cursor approval requires an interactive terminal.'
  };
  return new ClaudexError(code, messages[code]);
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function safeRepository(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
    || value.includes('\r') || value.includes('\n')) return false;
  const pathApi = /^[A-Za-z]:\\/u.test(value) || value.startsWith('\\\\') ? path.win32 : path.posix;
  return pathApi.isAbsolute(value) && pathApi.normalize(value) === value && value !== pathApi.parse(value).root;
}

function checkedNow(now) {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw fail();
  return value;
}

function checkedBinding(value, installationId) {
  try {
    if (!exact(value, ['repository', 'prompt', 'model', 'baseCommit', 'installationId'])
      || value.installationId !== installationId || !UUID.test(value.installationId)
      || !safeRepository(value.repository)
      || typeof value.model !== 'string' || value.model.length < 1 || value.model.length > 256 || /[\u0000-\u001f\u007f]/u.test(value.model)
      || !HEX.test(value.baseCommit)) throw fail();
    const prompt = normalizePromptForApproval(value.prompt);
    if (prompt.utf8.length < 1 || prompt.utf8.length > 32_768) throw fail();
    return { value, prompt };
  } catch { throw fail(); }
}

function metadata(approvalId, expiresAt, binding) {
  return {
    schemaVersion: 1, approvalId, expiresAt,
    binding: {
      repository: binding.repository, model: binding.model, baseCommit: binding.baseCommit,
      installationId: binding.installationId, promptSha256: binding.promptSha256
    }
  };
}

function aad(value) { return Buffer.from(JSON.stringify(value), 'utf8'); }

function validateRecord(record, installationId) {
  if (!exact(record, ['schemaVersion', 'approvalId', 'expiresAt', 'approved', 'binding', 'iv', 'ciphertext', 'tag'])
    || record.schemaVersion !== 1 || !ID.test(record.approvalId) || !Number.isSafeInteger(record.expiresAt)
    || typeof record.approved !== 'boolean'
    || !exact(record.binding, ['repository', 'model', 'baseCommit', 'installationId', 'promptSha256'])
    || record.binding.installationId !== installationId || !UUID.test(record.binding.installationId)
    || !safeRepository(record.binding.repository) || typeof record.binding.model !== 'string'
    || record.binding.model.length < 1 || record.binding.model.length > 256
    || /[\u0000-\u001f\u007f]/u.test(record.binding.model)
    || !HEX.test(record.binding.baseCommit) || !/^[0-9a-f]{64}$/u.test(record.binding.promptSha256)
    || !/^[A-Za-z0-9_-]{16}$/u.test(record.iv) || !/^[A-Za-z0-9_-]+$/u.test(record.ciphertext)
    || !/^[A-Za-z0-9_-]{22}$/u.test(record.tag)) throw fail('APPROVAL_INVALID');
  return record;
}

function decrypt(record, key) {
  try {
    const base = metadata(record.approvalId, record.expiresAt, record.binding);
    return key.withValue((bytes) => {
      const decipher = crypto.createDecipheriv('aes-256-gcm', bytes, Buffer.from(record.iv, 'base64url'));
      decipher.setAAD(aad(base));
      decipher.setAuthTag(Buffer.from(record.tag, 'base64url'));
      return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64url')), decipher.final()]);
    });
  } catch { throw fail('APPROVAL_INVALID'); }
}

function escapedPreview(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return [...text].slice(0, 160).join('').replaceAll('\\', '\\\\').replaceAll('\r', '\\r')
    .replaceAll('\n', '\\n').replaceAll('\t', '\\t').replace(/[\u0000-\u001f\u007f]/gu,
      (character) => `\\u${character.codePointAt(0).toString(16).padStart(4, '0')}`);
}

export function createCursorApprovalService({ manifestKey, installationId, store, now = Date.now, randomBytes = crypto.randomBytes } = {}) {
  if (!isSecret(manifestKey) || !UUID.test(installationId) || !store || typeof now !== 'function' || typeof randomBytes !== 'function'
    || ['createExclusive', 'read', 'replaceApproved', 'consumeAtomic', 'remove', 'list'].some((name) => typeof store[name] !== 'function')) throw fail();
  const key = deriveApprovalKey(manifestKey);
  const read = async (approvalId) => {
    if (!ID.test(approvalId)) throw fail('APPROVAL_INVALID');
    let record;
    try { record = await store.read(approvalId); } catch { throw fail(); }
    if (!record) throw fail('APPROVAL_INVALID');
    return validateRecord(record, installationId);
  };
  return Object.freeze({
    async request(rawBinding) {
      const { value, prompt } = checkedBinding(rawBinding, installationId);
      let idBytes;
      let iv;
      try { idBytes = Buffer.from(randomBytes(32)); iv = Buffer.from(randomBytes(12)); } catch { throw fail(); }
      if (idBytes.length !== 32 || iv.length !== 12) throw fail();
      const approvalId = idBytes.toString('base64url');
      idBytes.fill(0);
      const createdAt = checkedNow(now);
      if (createdAt > Number.MAX_SAFE_INTEGER - TTL_MS) throw fail();
      const expiresAt = createdAt + TTL_MS;
      const binding = { repository: value.repository, model: value.model, baseCommit: value.baseCommit, installationId, promptSha256: prompt.sha256 };
      const base = metadata(approvalId, expiresAt, binding);
      let encrypted;
      try {
        encrypted = key.withValue((bytes) => {
          const cipher = crypto.createCipheriv('aes-256-gcm', bytes, iv);
          cipher.setAAD(aad(base));
          return { ciphertext: Buffer.concat([cipher.update(prompt.utf8), cipher.final()]), tag: cipher.getAuthTag() };
        });
      } finally { prompt.utf8.fill(0); }
      const record = {
        ...base, approved: false, iv: iv.toString('base64url'),
        ciphertext: encrypted.ciphertext.toString('base64url'), tag: encrypted.tag.toString('base64url')
      };
      iv.fill(0); encrypted.ciphertext.fill(0); encrypted.tag.fill(0);
      let created;
      try { created = await store.createExclusive(record); } catch { throw fail(); }
      if (created !== true) throw fail();
      return Object.freeze({ code: 'APPROVAL_REQUIRED', approvalId, expiresAt });
    },
    async approve(approvalId, { isTTY, confirm } = {}) {
      if (isTTY !== true || typeof confirm !== 'function') throw fail('INTERACTION_REQUIRED');
      const record = await read(approvalId);
      const currentTime = checkedNow(now);
      if (record.approved || currentTime > record.expiresAt) {
        try { await store.remove(approvalId); } catch { throw fail(); }
        throw fail('APPROVAL_INVALID');
      }
      const prompt = decrypt(record, key);
      let accepted;
      try {
        accepted = await confirm(Object.freeze({
          repository: record.binding.repository, model: record.binding.model, baseCommit: record.binding.baseCommit,
          installationId, promptPreview: escapedPreview(prompt), promptDigest: record.binding.promptSha256, expiresAt: record.expiresAt
        }));
      } catch { throw fail('APPROVAL_INVALID'); }
      finally { prompt.fill(0); }
      if (accepted !== true) {
        try { await store.remove(approvalId); } catch { throw fail(); }
        throw fail('APPROVAL_INVALID');
      }
      const next = { ...record, approved: true };
      if (await store.replaceApproved(approvalId, record, next) !== true) throw fail('APPROVAL_INVALID');
      return Object.freeze({ action: 'approved', approvalId });
    },
    async consume(approvalId, rawBinding) {
      let checked;
      try { checked = checkedBinding(rawBinding, installationId); }
      catch { throw fail('APPROVAL_INVALID'); }
      const { value, prompt } = checked;
      const record = await read(approvalId);
      let currentTime;
      try { currentTime = checkedNow(now); } catch { prompt.utf8.fill(0); throw fail('APPROVAL_INVALID'); }
      if (!record.approved || currentTime > record.expiresAt) {
        try { await store.remove(approvalId); } catch { /* invalid remains unusable */ }
        prompt.utf8.fill(0); throw fail('APPROVAL_INVALID');
      }
      let plaintext;
      try { plaintext = decrypt(record, key); }
      catch { prompt.utf8.fill(0); throw fail('APPROVAL_INVALID'); }
      const bindingMatches = record.binding.repository === value.repository && record.binding.model === value.model
        && record.binding.baseCommit === value.baseCommit && record.binding.installationId === value.installationId
        && record.binding.promptSha256 === prompt.sha256 && plaintext.length === prompt.utf8.length
        && crypto.timingSafeEqual(plaintext, prompt.utf8);
      plaintext.fill(0); prompt.utf8.fill(0);
      if (!bindingMatches || await store.consumeAtomic(approvalId, record) !== true) throw fail('APPROVAL_INVALID');
      return Object.freeze({ action: 'consumed', approvalId });
    },
    async cleanup() {
      let records;
      try { records = await store.list(); } catch { throw fail(); }
      if (!Array.isArray(records) || records.length > 10_000) throw fail();
      for (const candidate of records) {
        let record;
        try {
          record = validateRecord(candidate, installationId);
        } catch { /* foreign/malformed protected records are not deletion authority */ }
        if (record) {
          try { await store.remove(record.approvalId); } catch { throw fail(); }
        }
      }
      return Object.freeze({ action: 'cleared' });
    }
  });
}
