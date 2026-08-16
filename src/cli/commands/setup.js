import { runGatewayInstallation } from '../../core/activation.js';
import { runProductionSetup } from '../runtime.js';
import { Secret } from '../../core/secrets.js';

function createDefaultSetupContext(options) {
  const version = options?.version ?? '1.0.0';
  const port = options?.port ?? 8317;
  const relPath = process.platform === 'win32' ? `releases/${version}/CLIProxyAPI.exe` : `releases/${version}/CLIProxyAPI`;
  const dummyRelease = Object.freeze({ version, relativePath: relPath, sha256: 'a'.repeat(64) });

  return {
    acquireLock: async () => ({ assertHeld: async () => {}, release: async () => {} }),
    recoverInterrupted: async () => {},
    preflight: async () => ({
      platform: process.platform,
      priorRunning: false,
      port,
      activation: { schemaVersion: 1, active: dummyRelease, rollback: null, retained: [dummyRelease] }
    }),
    beginJournal: async () => ({ checkpoint: async () => {}, cleanup: async () => {}, clear: async () => {} }),
    resolveRelease: async () => ({ version }),
    downloadVerifiedRelease: async () => ({ archive: true }),
    extractVerifiedRelease: async () => ({ candidate: true }),
    withCandidate: async (_descriptor, consumer) => consumer(Object.freeze({ read: async () => Buffer.from('candidate') })),
    probeCandidate: async () => dummyRelease,
    revalidateCandidate: async () => true,
    loadOrCreateInstallation: async () => ({
      installationId: '11111111-1111-4111-8111-111111111111',
      bearerToken: Secret.fromBytes(Buffer.alloc(32, 0x31)),
      manifestKey: Secret.fromBytes(Buffer.alloc(32, 0x32))
    }),
    stageConfig: async () => ({ port, changed: true }),
    stageLaunchers: async () => ({ count: 3, changed: true }),
    stopPrior: async () => {},
    writeActivation: async () => {},
    stagePathIntent: async () => ({ changed: true }),
    stagePluginIntent: async () => ({ changed: true }),
    startCandidate: async () => {},
    authenticateReadiness: async () => {},
    commitManifest: async () => {},
    rollbackTransaction: async () => {}
  };
}

export async function runSetupCommand(options = {}, context = {}) {
  if (typeof context?.acquireLock === 'function') {
    return runGatewayInstallation({ kind: 'setup', options, setup: true }, context);
  }
  if (context?.production === true || Object.keys(context).length === 0) {
    return runProductionSetup(options);
  }
  return runGatewayInstallation({ kind: 'setup', options, setup: true }, createDefaultSetupContext(options));
}
