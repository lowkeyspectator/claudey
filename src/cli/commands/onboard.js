import { beginnerNextSteps, ensureLocalInstall } from '../first-run.js';

export async function runOnboardCommand(options = {}, context = {}) {
  const installed = await ensureLocalInstall(context.environment ?? process.env, {
    loadInstallation: context.loadInstallation,
    runSetup: context.runSetup,
    announce: context.announce
  });
  const announce = context.announce ?? ((text) => {
    try { process.stderr.write(`${text}\n`); } catch { /* beginner guidance is best-effort */ }
  });
  announce(beginnerNextSteps());
  return Object.freeze({
    schemaVersion: 1,
    operation: 'onboard',
    version: installed.version,
    port: installed.port,
    next: Object.freeze(['claudey auth grok', 'claudey auth antigravity', 'claudey auth codex', 'claudey', 'claudey --yolo'])
  });
}
