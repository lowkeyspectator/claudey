import { ClaudeyError } from '../core/errors.js';

const assets = Object.freeze({
  'win32/x64': { suffix: 'windows_amd64.zip', archiveKind: 'zip' },
  'win32/arm64': { suffix: 'windows_aarch64.zip', archiveKind: 'zip' },
  'darwin/x64': { suffix: 'darwin_amd64.tar.gz', archiveKind: 'tar.gz' },
  'darwin/arm64': { suffix: 'darwin_aarch64.tar.gz', archiveKind: 'tar.gz' },
  'linux/x64': { suffix: 'linux_amd64.tar.gz', archiveKind: 'tar.gz' },
  'linux/arm64': { suffix: 'linux_aarch64.tar.gz', archiveKind: 'tar.gz' }
});

function unsupported(message) {
  return new ClaudeyError('PLATFORM_UNSUPPORTED', message);
}

function normalizeVersion(version) {
  const match = typeof version === 'string' && /^v?(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) throw unsupported('A stable CLIProxyAPI version is required for this platform.');
  return `${match[1]}.${match[2]}.${match[3]}`;
}

export function resolveReleaseAsset({ version, platform } = {}) {
  const runtimePlatform = platform?.runtimePlatform ?? platform?.platform;
  const runtimeArch = platform?.runtimeArch ?? platform?.arch;
  const descriptor = assets[`${runtimePlatform}/${runtimeArch}`];
  if (!descriptor) throw unsupported('This runtime platform and architecture are not supported.');

  const normalizedVersion = normalizeVersion(version);
  return {
    version: normalizedVersion,
    runtimePlatform,
    runtimeArch,
    archiveName: `CLIProxyAPI_${normalizedVersion}_${descriptor.suffix}`,
    archiveKind: descriptor.archiveKind
  };
}
