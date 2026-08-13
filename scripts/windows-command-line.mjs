function failure() {
  const error = new Error('The Windows argument is unsafe.');
  error.code = 'ARGUMENT_UNSAFE';
  return error;
}

export function quoteWindowsArgument(value) {
  if (typeof value !== 'string' || value.includes('\0')) throw failure();
  if (value.length > 32_767) throw failure();
  if (value.length > 0 && !/[\s"]/u.test(value)) return value;
  let result = '"';
  let backslashes = 0;
  for (const character of value) {
    if (character === '\\') { backslashes += 1; continue; }
    if (character === '"') result += `${'\\'.repeat(2 * backslashes + 1)}"`;
    else result += `${'\\'.repeat(backslashes)}${character}`;
    backslashes = 0;
  }
  result += `${'\\'.repeat(2 * backslashes)}"`;
  return result;
}

export function buildWindowsCommandLine(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 4_096) throw failure();
  const result = argv.map(quoteWindowsArgument).join(' ');
  if (result.length > 32_767) throw failure();
  return result;
}
