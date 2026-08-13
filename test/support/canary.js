export function assertNoCanary(text, canary) {
  if (String(text).includes(canary)) throw new Error('SECRET_CANARY_FOUND');
}
