import assert from 'node:assert/strict';
import test from 'node:test';

import { createCursorApprovalService } from '../../../src/cursor/approval.js';
import { Secret } from '../../../src/core/secrets.js';

const UUID = '11111111-1111-4111-8111-111111111111';
const KEY = Secret.fromBytes(Buffer.alloc(32, 0x44));
const BINDING = Object.freeze({
  repository: '/home/casey/project', prompt: 'exact\r\nprivate prompt canary Ω é',
  model: 'cursor-model', baseCommit: 'a'.repeat(40), installationId: UUID
});

function fixture({ now = 1_000, randomByte = 0x21 } = {}) {
  const records = new Map();
  const events = [];
  const store = {
    createExclusive: async (record) => {
      events.push(['create', structuredClone(record)]);
      if (records.has(record.approvalId)) return false;
      records.set(record.approvalId, structuredClone(record)); return true;
    },
    read: async (id) => records.has(id) ? structuredClone(records.get(id)) : null,
    replaceApproved: async (id, expected, next) => {
      const current = records.get(id);
      if (JSON.stringify(current) !== JSON.stringify(expected)) return false;
      records.set(id, structuredClone(next)); return true;
    },
    consumeAtomic: async (id, expected) => {
      const current = records.get(id);
      if (JSON.stringify(current) !== JSON.stringify(expected)) return false;
      records.delete(id); return true;
    },
    remove: async (id) => records.delete(id),
    list: async () => [...records.values()].map((record) => structuredClone(record))
  };
  const service = createCursorApprovalService({
    manifestKey: KEY, installationId: UUID, store,
    now: () => now,
    randomBytes: (size) => Buffer.alloc(size, randomByte)
  });
  return { service, records, events, setNow: (value) => { now = value; } };
}

test('creates a 256-bit five-minute encrypted approval with authenticated binding and no plaintext canary', async () => {
  const f = fixture();
  const requested = await f.service.request(BINDING);
  assert.equal(requested.code, 'APPROVAL_REQUIRED');
  assert.equal(requested.approvalId, Buffer.alloc(32, 0x21).toString('base64url'));
  assert.equal(requested.expiresAt, 301_000);
  const serialized = JSON.stringify(f.records.get(requested.approvalId));
  assert.equal(serialized.includes('private prompt canary'), false);
  assert.equal(serialized.includes('Ω'), false);
  assert.equal(f.records.get(requested.approvalId).binding.promptSha256.length, 64);
});

test('TTY approval displays canonical binding, safely escaped preview, full digest and expiry without persisting plaintext', async () => {
  const f = fixture();
  const { approvalId } = await f.service.request(BINDING);
  let display;
  const result = await f.service.approve(approvalId, {
    isTTY: true,
    confirm: async (value) => { display = value; return true; }
  });
  assert.equal(result.action, 'approved');
  assert.equal(display.repository, BINDING.repository);
  assert.equal(display.model, BINDING.model);
  assert.equal(display.baseCommit, BINDING.baseCommit);
  assert.equal(display.promptDigest.length, 64);
  assert.match(display.promptPreview, /\\r\\n/u);
  assert.equal(JSON.stringify(f.records.get(approvalId)).includes('private prompt canary'), false);
  await assert.rejects(f.service.approve(approvalId, { isTTY: false, confirm: async () => true }),
    (error) => error.code === 'INTERACTION_REQUIRED');
});

test('consumes an exact approved binding once and rejects replay, swaps, expiry, and byte changes', async () => {
  const f = fixture();
  const { approvalId } = await f.service.request(BINDING);
  await f.service.approve(approvalId, { isTTY: true, confirm: async () => true });
  for (const changed of [
    { ...BINDING, repository: '/home/casey/other' }, { ...BINDING, model: 'other' },
    { ...BINDING, baseCommit: 'b'.repeat(40) }, { ...BINDING, installationId: '22222222-2222-4222-8222-222222222222' },
    { ...BINDING, prompt: BINDING.prompt.replace('\r\n', '\n') }, { ...BINDING, prompt: BINDING.prompt.normalize('NFD') }
  ]) await assert.rejects(f.service.consume(approvalId, changed), (error) => error.code === 'APPROVAL_INVALID');
  assert.deepEqual(await f.service.consume(approvalId, BINDING), { action: 'consumed', approvalId });
  await assert.rejects(f.service.consume(approvalId, BINDING), (error) => error.code === 'APPROVAL_INVALID');

  const expired = fixture();
  const request = await expired.service.request(BINDING);
  await expired.service.approve(request.approvalId, { isTTY: true, confirm: async () => true });
  expired.setNow(301_001);
  await assert.rejects(expired.service.consume(request.approvalId, BINDING), (error) => error.code === 'APPROVAL_INVALID');
  assert.equal(expired.records.has(request.approvalId), false);
});

test('atomic consumption permits exactly one concurrent winner', async () => {
  const f = fixture();
  const { approvalId } = await f.service.request(BINDING);
  await f.service.approve(approvalId, { isTTY: true, confirm: async () => true });
  const outcomes = await Promise.allSettled([
    f.service.consume(approvalId, BINDING), f.service.consume(approvalId, BINDING)
  ]);
  assert.equal(outcomes.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter(({ status }) => status === 'rejected' && status).length, 1);
});

test('decline, invalid records, RNG failures, and cleanup remove records without leaking diagnostics or plaintext', async () => {
  const declined = fixture();
  const { approvalId } = await declined.service.request(BINDING);
  await assert.rejects(declined.service.approve(approvalId, { isTTY: true, confirm: async () => false }),
    (error) => error.code === 'APPROVAL_INVALID');
  assert.equal(declined.records.has(approvalId), false);
  const f = fixture();
  const first = await f.service.request(BINDING);
  await f.service.cleanup();
  assert.equal(f.records.has(first.approvalId), false);
  const badRng = createCursorApprovalService({
    manifestKey: KEY, installationId: UUID,
    store: {
      createExclusive: async () => true, read: async () => null, replaceApproved: async () => false,
      consumeAtomic: async () => false, remove: async () => undefined, list: async () => []
    },
    now: () => 1, randomBytes: () => Buffer.alloc(31)
  });
  await assert.rejects(badRng.request(BINDING), (error) => error.code === 'SAFETY_REFUSAL');
});

test('binds registered canonical Windows repository paths without weakening exact byte matching', async () => {
  const f = fixture();
  const binding = { ...BINDING, repository: 'C:\\Users\\Casey\\project' };
  const { approvalId } = await f.service.request(binding);
  await f.service.approve(approvalId, { isTTY: true, confirm: async () => true });
  assert.deepEqual(await f.service.consume(approvalId, binding), { action: 'consumed', approvalId });
});

test('refuses a non-integer clock at approval and consumption boundaries', async () => {
  const approving = fixture();
  const pending = await approving.service.request(BINDING);
  approving.setNow(Number.NaN);
  await assert.rejects(approving.service.approve(pending.approvalId, { isTTY: true, confirm: async () => true }),
    (error) => error.code === 'SAFETY_REFUSAL');

  const consuming = fixture();
  const approved = await consuming.service.request(BINDING);
  await consuming.service.approve(approved.approvalId, { isTTY: true, confirm: async () => true });
  consuming.setNow(Number.NaN);
  await assert.rejects(consuming.service.consume(approved.approvalId, BINDING),
    (error) => error.code === 'APPROVAL_INVALID');
});
