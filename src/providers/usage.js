import fs from 'node:fs/promises';
import path from 'node:path';

function normalizeName(value) {
  return typeof value === 'string' ? value.toLowerCase().replace(/[^a-z0-9]+/g, '') : '';
}

function remainingFromWindow(window) {
  if (!window || typeof window !== 'object') return null;
  const used = Number(window.used_percent ?? window.usedPercent);
  if (!Number.isFinite(used)) return null;
  return Math.max(0, Math.min(100, Math.round(100 - used)));
}

function resetAtFromWindow(window) {
  if (!window || typeof window !== 'object') return null;
  if (typeof window.reset_at === 'number' && Number.isFinite(window.reset_at)) {
    return new Date(window.reset_at * 1000).toISOString();
  }
  if (typeof window.resetTime === 'string') return window.resetTime;
  if (typeof window.reset_after_seconds === 'number') {
    return new Date(Date.now() + window.reset_after_seconds * 1000).toISOString();
  }
  return null;
}

function windowLabel(seconds) {
  if (seconds === 18_000) return '5h';
  if (seconds === 604_800) return '7d';
  if (Number.isFinite(seconds) && seconds > 0) return `${Math.round(seconds / 3600)}h`;
  return null;
}

async function readAuthRecords(authDir) {
  if (typeof authDir !== 'string' || authDir.length < 2) return [];
  let names;
  try { names = await fs.readdir(authDir); } catch { return []; }
  const records = [];
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    let parsed;
    try { parsed = JSON.parse(await fs.readFile(path.join(authDir, name), 'utf8')); } catch { continue; }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.access_token !== 'string' || typeof parsed.type !== 'string') continue;
    records.push({
      type: parsed.type,
      accessToken: parsed.access_token,
      accountId: typeof parsed.account_id === 'string' ? parsed.account_id : null,
      projectId: typeof parsed.project_id === 'string' ? parsed.project_id : null
    });
  }
  return records;
}

async function fetchJson(fetchImpl, url, options = {}) {
  try {
    const signal = options.signal ?? (typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(5000) : undefined);
    const response = await fetchImpl(url, { ...options, signal });
    if (!response || typeof response.json !== 'function') return null;
    if (response.status !== 200) return null;
    return await response.json();
  } catch {
    return null;
  }
}

async function collectCodexUsage(record, fetchImpl) {
  const headers = { authorization: `Bearer ${record.accessToken}`, accept: 'application/json' };
  if (record.accountId) headers['chatgpt-account-id'] = record.accountId;
  const payload = await fetchJson(fetchImpl, 'https://chatgpt.com/backend-api/wham/usage', { headers });
  if (!payload || typeof payload !== 'object') return { provider: 'codex', status: 'unavailable' };
  const rate = payload.rate_limit && typeof payload.rate_limit === 'object' ? payload.rate_limit : {};
  const primary = rate.primary_window ?? null;
  const extras = [];
  if (Array.isArray(payload.additional_rate_limits)) {
    for (const item of payload.additional_rate_limits) {
      if (!item || typeof item !== 'object') continue;
      const nested = item.rate_limit && typeof item.rate_limit === 'object' ? item.rate_limit : {};
      extras.push({
        name: typeof item.limit_name === 'string' ? item.limit_name : '',
        remainingPercent: remainingFromWindow(nested.primary_window),
        resetAt: resetAtFromWindow(nested.primary_window),
        window: windowLabel(nested.primary_window?.limit_window_seconds),
        allowed: nested.allowed === true
      });
    }
  }
  return {
    provider: 'codex',
    status: rate.limit_reached === true ? 'exhausted' : rate.allowed === false ? 'limited' : 'available',
    plan: typeof payload.plan_type === 'string' ? payload.plan_type : null,
    remainingPercent: remainingFromWindow(primary),
    resetAt: resetAtFromWindow(primary),
    window: windowLabel(primary?.limit_window_seconds),
    extras
  };
}

async function collectAntigravityUsage(record, fetchImpl) {
  if (!record.projectId) return { provider: 'antigravity', status: 'unavailable' };
  const payload = await fetchJson(fetchImpl, 'https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota', {
    method: 'POST',
    headers: { authorization: `Bearer ${record.accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ project: record.projectId })
  });
  const buckets = Array.isArray(payload?.buckets) ? payload.buckets : [];
  const extras = buckets.map((bucket) => {
    const remaining = Number(bucket?.remainingFraction);
    return {
      name: typeof bucket?.modelId === 'string' ? bucket.modelId : '',
      remainingPercent: Number.isFinite(remaining) ? Math.round(remaining * 100) : null,
      resetAt: typeof bucket?.resetTime === 'string' ? bucket.resetTime : null,
      window: null,
      allowed: Number.isFinite(remaining) ? remaining > 0 : null
    };
  }).filter((item) => item.name);
  return {
    provider: 'antigravity',
    status: extras.length > 0 ? 'available' : 'unavailable',
    plan: null,
    remainingPercent: extras.length > 0 ? Math.min(...extras.map((item) => item.remainingPercent ?? 100)) : null,
    resetAt: extras[0]?.resetAt ?? null,
    window: null,
    extras
  };
}

async function collectGrokUsage(record, fetchImpl) {
  const payload = await fetchJson(fetchImpl, 'https://api.x.ai/v1/models', {
    headers: { authorization: `Bearer ${record.accessToken}`, accept: 'application/json' }
  });
  const extras = Array.isArray(payload?.data)
    ? payload.data.filter((model) => model && typeof model.id === 'string').map((model) => ({
      name: model.id,
      remainingPercent: null,
      resetAt: null,
      window: Number.isFinite(model.context_length) ? `${model.context_length} ctx` : null,
      allowed: true
    }))
    : [];
  return {
    provider: 'grok',
    status: extras.length > 0 ? 'available' : 'unavailable',
    plan: 'xai-oauth',
    remainingPercent: null,
    resetAt: null,
    window: extras[0]?.window ?? null,
    extras
  };
}

function matchExtra(modelId, extras) {
  const needle = normalizeName(modelId);
  if (!needle) return null;
  return extras.find((item) => {
    const name = normalizeName(item.name);
    return name && (name === needle || name.includes(needle) || needle.includes(name));
  }) ?? null;
}

export function usageForModel(model, collected = {}) {
  const provider = model?.owned_by;
  const pack = collected[provider];
  if (!pack) return Object.freeze({ remainingPercent: null, resetAt: null, window: null, status: 'unknown' });
  const extra = matchExtra(model.id, pack.extras ?? []);
  if (extra) {
    return Object.freeze({
      remainingPercent: extra.remainingPercent,
      resetAt: extra.resetAt,
      window: extra.window,
      status: extra.allowed === false ? 'exhausted' : extra.allowed === true ? 'available' : pack.status
    });
  }
  if (provider !== 'codex') {
    return Object.freeze({ remainingPercent: null, resetAt: pack.resetAt, window: pack.window, status: pack.status });
  }
  return Object.freeze({
    remainingPercent: pack.remainingPercent ?? null,
    resetAt: pack.resetAt ?? null,
    window: pack.window ?? null,
    status: pack.status
  });
}

export function attachUsage(result, collected) {
  if (!result || typeof result !== 'object') return result;
  if (Array.isArray(result.models)) {
    return Object.freeze({
      ...result,
      models: Object.freeze(result.models.map((model) => Object.freeze({ ...model, usage: usageForModel(model, collected) })))
    });
  }
  if (Array.isArray(result.providers)) {
    return Object.freeze({
      ...result,
      providers: Object.freeze(result.providers.map((provider) => attachUsage(provider, collected)))
    });
  }
  return result;
}

export async function collectProviderUsage({ authDir, fetchImpl = fetch } = {}) {
  const records = await readAuthRecords(authDir);
  const collected = {};
  for (const record of records) {
    try {
      if (record.type === 'codex') collected.codex = await collectCodexUsage(record, fetchImpl);
      else if (record.type === 'antigravity') collected.antigravity = await collectAntigravityUsage(record, fetchImpl);
      else if (record.type === 'xai' || record.type === 'grok') collected.grok = await collectGrokUsage(record, fetchImpl);
    } catch {
      collected[record.type === 'xai' ? 'grok' : record.type] = { provider: record.type, status: 'unavailable' };
    }
  }
  return Object.freeze(collected);
}

export function formatUsageLine(model) {
  const usage = model?.usage;
  if (!usage) return model.id;
  const parts = [model.id];
  if (Number.isFinite(usage.remainingPercent)) parts.push(`${usage.remainingPercent}% left`);
  else if (usage.window) parts.push(String(usage.window));
  if (usage.status && usage.status !== 'available' && usage.status !== 'unknown') parts.push(usage.status);
  return parts.join(' · ');
}
