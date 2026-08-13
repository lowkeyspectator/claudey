import crypto from 'node:crypto';
import util from 'node:util';

function safetyError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

export class Secret {
  #bytes;

  constructor(bytes) {
    this.#bytes = Buffer.from(bytes);
    Object.defineProperty(this, 'value', {
      enumerable: true,
      get: () => { throw safetyError('SECRET_SERIALIZATION_REFUSED'); }
    });
  }

  static fromBytes(bytes) {
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError('Secret requires bytes.');
    return new Secret(bytes);
  }

  withValue(callback) {
    if (this.#bytes === undefined) throw safetyError('SECRET_DISPOSED');
    const scoped = Buffer.from(this.#bytes);
    try {
      return callback(scoped);
    } finally {
      scoped.fill(0);
    }
  }

  dispose() {
    if (this.#bytes) this.#bytes.fill(0);
    this.#bytes = undefined;
  }

  toJSON() { throw safetyError('SECRET_SERIALIZATION_REFUSED'); }
  toString() { throw safetyError('SECRET_ACCESS_REFUSED'); }
  valueOf() { throw safetyError('SECRET_ACCESS_REFUSED'); }
  [Symbol.toPrimitive]() { throw safetyError('SECRET_ACCESS_REFUSED'); }
  [util.inspect.custom]() { throw safetyError('SECRET_INSPECTION_REFUSED'); }
}

export function isSecret(value) {
  return value instanceof Secret;
}

export function normalizePromptForApproval(prompt) {
  if (typeof prompt !== 'string' || prompt.includes('\0')) {
    const error = new Error('Prompt must be a string without NUL bytes.');
    error.code = 'USAGE_ERROR';
    throw error;
  }
  const utf8 = Buffer.from(prompt, 'utf8');
  return { utf8, sha256: crypto.createHash('sha256').update(utf8).digest('hex') };
}
