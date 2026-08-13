export function assertPlainObject(value, label = 'value') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    const error = new Error(`${label} must be an object.`);
    error.code = 'USAGE_ERROR';
    throw error;
  }
  return value;
}
