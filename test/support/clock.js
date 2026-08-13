export function fixedClock(now = new Date('2026-08-12T00:00:00.000Z')) {
  return { now: () => new Date(now) };
}
