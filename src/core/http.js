import https from 'node:https';
import { URL } from 'node:url';

function headerMap(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    const key = name.toLowerCase();
    let normalized = Array.isArray(value) ? value.join(', ') : value;
    if (key === 'content-type' && typeof normalized === 'string') {
      normalized = normalized.split(';')[0].trim().toLowerCase();
    }
    result[key] = normalized;
  }
  return result;
}

export function createOfficialHttpsClient() {
  return {
    async get(url, { signal, deadlineMs } = {}) {
      const parsed = new URL(url);
      return new Promise((resolve, reject) => {
        const request = https.get({
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: `${parsed.pathname}${parsed.search}`,
          headers: {
            accept: 'application/vnd.github+json, application/octet-stream, */*',
            'user-agent': 'claudeyctl/1.0'
          }
        }, (response) => {
          const chunks = [];
          response.on('data', (chunk) => chunks.push(chunk));
          response.on('error', reject);
          response.on('end', () => {
            const body = Buffer.concat(chunks);
            resolve({
              status: response.statusCode,
              headers: headerMap(response.headers),
              body: {
                async *[Symbol.asyncIterator]() {
                  yield body;
                }
              }
            });
          });
        });
        request.on('error', reject);
        if (Number.isSafeInteger(deadlineMs) && deadlineMs > 0) {
          request.setTimeout(deadlineMs, () => {
            request.destroy();
            reject(new Error('Request timed out.'));
          });
        }
        const onAbort = () => {
          request.destroy();
          reject(new Error('Request aborted.'));
        };
        if (signal?.aborted) onAbort();
        else signal?.addEventListener('abort', onAbort, { once: true });
      });
    }
  };
}
