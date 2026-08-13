import { ClaudexError } from '../core/errors.js';

const COMMANDS = new Set(['cursor-agent', 'agent']);
const SOURCES = new Set(['path', 'fallback']);
const BINDINGS = new WeakSet();
const REVALIDATE = new WeakMap();

function unsupported() {
  return new ClaudexError('CAPABILITY_UNSUPPORTED', 'A verified Cursor Agent executable is unavailable.');
}

function candidatesOf(value) {
  try {
    if (!Array.isArray(value) || value.length === 0 || value.length > 64) throw unsupported();
    const result = value.map((candidate) => {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
        || Object.keys(candidate).sort().join(',') !== 'command,source,target'
        || !COMMANDS.has(candidate.command) || !SOURCES.has(candidate.source)
        || !candidate.target || typeof candidate.target !== 'object') throw unsupported();
      return Object.freeze({ command: candidate.command, source: candidate.source, target: candidate.target });
    });
    for (let left = 0; left < result.length; left += 1) {
      for (let right = left + 1; right < result.length; right += 1) {
        if (result[left].command === result[right].command && result[left].source === result[right].source) throw unsupported();
      }
    }
    return result;
  } catch { throw unsupported(); }
}

export async function resolveCursorAgentExecutable({ candidates, verifyTarget, verifyVersion } = {}) {
  if (typeof verifyTarget !== 'function' || typeof verifyVersion !== 'function') throw unsupported();
  const ordered = candidatesOf(candidates).sort((left, right) => {
    const command = (left.command === 'cursor-agent' ? 0 : 1) - (right.command === 'cursor-agent' ? 0 : 1);
    return command || (left.source === 'path' ? 0 : 1) - (right.source === 'path' ? 0 : 1);
  });
  for (const candidate of ordered) {
    let target;
    let versionOk = false;
    try {
      target = await verifyTarget(candidate);
      if (!target || typeof target !== 'object' || !Object.isFrozen(target)) continue;
      versionOk = await verifyVersion(target) === true;
    } catch { continue; }
    if (versionOk) {
      const binding = Object.freeze({ command: candidate.command, source: candidate.source, target });
      BINDINGS.add(binding);
      REVALIDATE.set(binding, async () => {
        try {
          const current = await verifyTarget(candidate);
          return current === target && await verifyVersion(target) === true;
        } catch { return false; }
      });
      return binding;
    }
  }
  throw unsupported();
}

export function isCursorExecutableBinding(value) {
  return Boolean(value && typeof value === 'object' && BINDINGS.has(value));
}

export async function revalidateCursorExecutableBinding(value) {
  if (!isCursorExecutableBinding(value)) return false;
  return await REVALIDATE.get(value)() === true;
}
