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
      accountId: typeof parsed.account_id === 'string' ? parsed.account_id
        : typeof parsed.sub === 'string' ? parsed.sub : null,
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

function remainingFromUsedPercent(used) {
  const value = Number(used);
  if (!Number.isFinite(value)) return null;
  return Math.max(0, Math.min(100, Math.round(100 - value)));
}

function periodWindow(type) {
  if (typeof type !== 'string') return null;
  if (/WEEKLY/i.test(type)) return '7d';
  if (/MONTHLY/i.test(type)) return '30d';
  return null;
}

async function collectGrokUsage(record, fetchImpl) {
  const headers = { authorization: `Bearer ${record.accessToken}`, accept: 'application/json' };
  if (record.accountId) headers['x-userid'] = record.accountId;
  const user = await fetchJson(fetchImpl, 'https://cli-chat-proxy.grok.com/v1/user', { headers });
  if (typeof user?.userId === 'string' && user.userId.length > 0) headers['x-userid'] = user.userId;
  const billing = await fetchJson(fetchImpl, 'https://cli-chat-proxy.grok.com/v1/billing?format=credits', { headers });
  const config = billing?.config && typeof billing.config === 'object' ? billing.config : {};
  const remainingPercent = remainingFromUsedPercent(config.creditUsagePercent ?? config.credit_usage_percent);
  const period = config.currentPeriod ?? config.current_period ?? {};
  const resetAt = typeof period.end === 'string' ? period.end
    : typeof config.billingPeriodEnd === 'string' ? config.billingPeriodEnd
      : typeof config.billing_period_end === 'string' ? config.billing_period_end : null;
  const extras = [];
  if (Array.isArray(config.productUsage)) {
    for (const item of config.productUsage) {
      if (!item || typeof item !== 'object') continue;
      const name = typeof item.product === 'string' ? item.product : '';
      if (!name) continue;
      extras.push({
        name,
        remainingPercent: remainingFromUsedPercent(item.usagePercent ?? item.usage_percent),
        resetAt,
        window: periodWindow(period.type),
        allowed: remainingFromUsedPercent(item.usagePercent ?? item.usage_percent) !== 0
      });
    }
  }
  const models = await fetchJson(fetchImpl, 'https://api.x.ai/v1/models', {
    headers: { authorization: `Bearer ${record.accessToken}`, accept: 'application/json' }
  });
  if (Array.isArray(models?.data)) {
    for (const model of models.data) {
      if (!model || typeof model.id !== 'string') continue;
      extras.push({
        name: model.id,
        remainingPercent,
        resetAt,
        window: Number.isFinite(model.context_length) ? `${model.context_length} ctx` : periodWindow(period.type),
        allowed: remainingPercent !== 0
      });
    }
  }
  const status = remainingPercent === 0 ? 'exhausted'
    : remainingPercent != null || extras.length > 0 ? 'available' : 'unavailable';
  return {
    provider: 'grok',
    status,
    plan: typeof billing?.subscriptionTier === 'string' ? billing.subscriptionTier : 'xai-oauth',
    remainingPercent,
    resetAt,
    window: periodWindow(period.type),
    extras
  };
}

function cursorStateDatabase(env = process.env) {
  if (typeof env.APPDATA === 'string' && env.APPDATA.length > 0) {
    return path.join(env.APPDATA, 'Cursor', 'User', 'globalStorage', 'state.vscdb');
  }
  if (typeof env.HOME === 'string' && env.HOME.length > 0 && process.platform === 'darwin') {
    return path.join(env.HOME, 'Library', 'Application Support', 'Cursor', 'User', 'globalStorage', 'state.vscdb');
  }
  if (typeof env.HOME === 'string' && env.HOME.length > 0) {
    const config = typeof env.XDG_CONFIG_HOME === 'string' && env.XDG_CONFIG_HOME.length > 0
      ? env.XDG_CONFIG_HOME : path.join(env.HOME, '.config');
    return path.join(config, 'Cursor', 'User', 'globalStorage', 'state.vscdb');
  }
  return null;
}

async function loadSqlite() {
  try {
    return await import('node:sqlite');
  } catch {
    return null;
  }
}

async function defaultReadCursorToken(env) {
  const target = cursorStateDatabase(env);
  if (!target) return null;
  const sqlite = await loadSqlite();
  if (!sqlite?.DatabaseSync) return null;
  try {
    const database = new sqlite.DatabaseSync(target, { readOnly: true });
    try {
      const row = database.prepare("SELECT value FROM ItemTable WHERE key = 'cursorAuth/accessToken'").get();
      if (!row || (typeof row.value !== 'string' && typeof row.value !== 'object')) return null;
      const value = String(row.value ?? '');
      if (value.length < 8) return null;
      return value.replace(/^"|"$/g, '');
    } finally {
      database.close();
    }
  } catch {
    return null;
  }
}

async function collectCursorUsage({ fetchImpl, environment = process.env, readCursorToken } = {}) {
  const token = await (readCursorToken ?? defaultReadCursorToken)(environment);
  if (!token) return { provider: 'cursor', status: 'unavailable' };
  const payload = await fetchJson(fetchImpl, 'https://api2.cursor.sh/aiserver.v1.DashboardService/GetCurrentPeriodUsage', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'connect-protocol-version': '1'
    },
    body: '{}'
  });
  if (!payload || typeof payload !== 'object') return { provider: 'cursor', status: 'unavailable' };
  const plan = payload.planUsage && typeof payload.planUsage === 'object' ? payload.planUsage : {};
  const remainingPercent = remainingFromUsedPercent(plan.totalPercentUsed);
  const autoRemaining = remainingFromUsedPercent(plan.autoPercentUsed);
  const apiRemaining = remainingFromUsedPercent(plan.apiPercentUsed);
  const cycleEnd = payload.billingCycleEnd;
  const resetAt = typeof cycleEnd === 'number' && Number.isFinite(cycleEnd) ? new Date(cycleEnd).toISOString()
    : typeof cycleEnd === 'string' && /^\d+$/u.test(cycleEnd) ? new Date(Number(cycleEnd)).toISOString()
      : typeof cycleEnd === 'string' ? cycleEnd : null;
  const extras = [];
  if (Array.isArray(payload?.autoBucketModels)) {
    for (const name of payload.autoBucketModels) {
      if (typeof name !== 'string' || name.length === 0) continue;
      extras.push({
        name,
        remainingPercent: autoRemaining,
        resetAt,
        window: 'auto',
        allowed: autoRemaining !== 0
      });
    }
  }
  const status = remainingPercent === 0 || plan.totalPercentUsed >= 100 ? 'exhausted'
    : remainingPercent != null ? 'available' : 'unavailable';
  return {
    provider: 'cursor',
    status,
    plan: typeof payload?.displayMessage === 'string' ? 'cursor' : 'cursor',
    remainingPercent: remainingPercent ?? apiRemaining ?? autoRemaining,
    resetAt,
    window: 'cycle',
    extras: extras.length > 0 ? extras : [{
      name: 'api',
      remainingPercent: apiRemaining,
      resetAt,
      window: 'api',
      allowed: apiRemaining !== 0
    }]
  };
}

function matchExtra(modelId, extras) {
  const needle = normalizeName(modelId);
  if (!needle) return null;
  const scored = extras.map((item) => {
    const name = normalizeName(item.name);
    if (!name) return { item, score: 0 };
    if (name === needle) return { item, score: 3 };
    if (needle.includes(name) || name.includes(needle)) return { item, score: 2 };
    const family = name.replace(/(thinking|agent|preview|fast|low|high|medium|xhigh|extra)+/g, '');
    const other = needle.replace(/(thinking|agent|preview|fast|low|high|medium|xhigh|extra)+/g, '');
    if (family && other && (family === other || family.includes(other) || other.includes(family))) {
      return { item, score: 1 };
    }
    return { item, score: 0 };
  }).filter((entry) => entry.score > 0).sort((left, right) => right.score - left.score);
  return scored[0]?.item ?? null;
}

export function usageForModel(model, collected = {}) {
  const provider = model?.owned_by;
  const pack = collected[provider];
  if (!pack) return Object.freeze({ remainingPercent: null, resetAt: null, window: null, status: 'unknown' });
  const extra = matchExtra(model.id, pack.extras ?? []);
  if (extra) {
    return Object.freeze({
      remainingPercent: extra.remainingPercent ?? pack.remainingPercent ?? null,
      resetAt: extra.resetAt ?? pack.resetAt ?? null,
      window: extra.window ?? pack.window ?? null,
      status: extra.allowed === false ? 'exhausted' : extra.allowed === true ? 'available' : pack.status
    });
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
      models: Object.freeze(result.models.map((model) => {
        const record = typeof model === 'string'
          ? { id: model, owned_by: result.provider }
          : model;
        return Object.freeze({ ...record, usage: usageForModel(record, collected) });
      }))
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

export async function collectProviderUsage({
  authDir, fetchImpl = fetch, environment = process.env, readCursorToken
} = {}) {
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
  try {
    collected.cursor = await collectCursorUsage({ fetchImpl, environment, readCursorToken });
  } catch {
    collected.cursor = { provider: 'cursor', status: 'unavailable' };
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
