import { ClaudeyError } from '../core/errors.js';
import { getManagedPaths } from '../core/paths.js';
import { detectPlatform } from './detect.js';
import * as linux from './linux.js';
import * as macos from './macos.js';
import * as windows from './windows.js';

const adapters = Object.freeze({ windows, macos, linux });

export { detectPlatform, getManagedPaths };

export function getPlatformAdapter(platform) {
  const family = typeof platform === 'string' ? platform : platform?.family;
  const adapter = adapters[family];
  if (!adapter) throw new ClaudeyError('PLATFORM_UNSUPPORTED', 'This platform adapter is not supported.');
  return adapter;
}
