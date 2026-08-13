export function createSpawner(result = { code: 0, stdout: '', stderr: '' }) {
  return { spawn: async () => result };
}
