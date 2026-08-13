export function createTerminal({ interactive = true } = {}) {
  return { isInteractive: () => interactive };
}
