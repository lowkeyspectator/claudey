function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function asAsyncBody(route, signal, request) {
  if (route.body) return route.body;

  return (async function* body() {
    for (const [index, chunk] of (route.chunks ?? []).entries()) {
      const delayMs = Array.isArray(route.delays) ? route.delays[index] : route.delayMs;
      if (delayMs) await sleep(delayMs);
      if (signal?.aborted) {
        const error = new Error('The request was aborted.');
        error.name = 'AbortError';
        throw error;
      }
      if (route.errorAtChunk === chunk) throw route.error;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      request.consumedBytes += bytes.length;
      yield bytes;
    }
    if (route.error) throw route.error;
  })();
}

function routeFor(routes, url) {
  if (routes instanceof Map) return routes.get(url);
  return routes[url];
}

export function createReleaseHttp({ routes = new Map() } = {}) {
  const requests = [];
  const aborts = [];

  return {
    requests,
    aborts,
    async get(url, { signal, deadlineMs } = {}) {
      const request = { url, deadlineMs, responseHeaders: undefined, status: undefined, consumedBytes: 0, aborted: false };
      requests.push(request);
      const route = routeFor(routes, url);
      if (!route) {
        const error = new Error(`No scripted route for ${url}`);
        error.code = 'NO_SCRIPTED_ROUTE';
        throw error;
      }
      if (signal) {
        signal.addEventListener('abort', () => {
          request.aborted = true;
          aborts.push(url);
        }, { once: true });
      }
      if (route.throw) throw route.throw;
      const headers = route.headers ?? {};
      request.responseHeaders = headers;
      request.status = route.status ?? 200;
      if (route.waitForAbort) {
        await new Promise((resolve) => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener('abort', resolve, { once: true });
        });
      }
      return {
        status: route.status ?? 200,
        headers,
        body: asAsyncBody(route, signal, request)
      };
    }
  };
}

export function releaseAsset({ name, url, size = 5, contentType = 'application/octet-stream' }) {
  return { name, browser_download_url: url, size, content_type: contentType };
}

export function releaseRecord({ tag = 'v7.2.130', draft = false, prerelease = false, assets = [] } = {}) {
  return {
    tag_name: tag,
    draft,
    prerelease,
    published_at: '2026-08-12T10:30:00Z',
    assets
  };
}
