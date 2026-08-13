import { ClaudexError } from '../core/errors.js';
import { detectLinux } from './linux.js';
import { detectMacos } from './macos.js';
import { detectWindows } from './windows.js';

function unsupported(message) {
  return new ClaudexError('PLATFORM_UNSUPPORTED', message);
}

const detectors = Object.freeze({
  win32: detectWindows,
  darwin: detectMacos,
  linux: detectLinux
});

function runtimeInfo(input) {
  const runtimePlatform = input?.runtime?.platform;
  const runtimeArch = input?.runtime?.arch;
  if (!detectors[runtimePlatform] || !['x64', 'arm64'].includes(runtimeArch)) {
    throw unsupported('This runtime platform and architecture are not supported.');
  }
  return { runtimePlatform, runtimeArch };
}

function architectureWarnings(runtimeArch, nativeArch) {
  if (runtimeArch === nativeArch) return [];
  return [{ code: 'RUNTIME_NATIVE_ARCH_MISMATCH', runtimeArch, nativeArch }];
}

export function detectPlatform(input = {}) {
  const { runtimePlatform, runtimeArch } = runtimeInfo(input);
  const nativeArch = input.nativeArch ?? runtimeArch;
  const platform = detectors[runtimePlatform](input);
  return {
    ...platform,
    runtimePlatform,
    runtimeArch,
    nativeArch,
    warnings: architectureWarnings(runtimeArch, nativeArch)
  };
}
