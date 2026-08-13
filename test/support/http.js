export function createHttpStub(routes = new Map()) {
  return { get: async (url) => routes.get(url) };
}
