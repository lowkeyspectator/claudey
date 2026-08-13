import { failEnvelope, ok } from '../core/result.js';

function line(value) {
  return `${value}\n`;
}

export function isColorSupported({ noColor = false } = {}, io = process) {
  if (noColor) return false;
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(io?.stdout?.isTTY || io?.stderr?.isTTY);
}

export function whiteVisible(text, options = {}, io = process) {
  if (!isColorSupported(options, io)) return text;
  return `\x1b[1;97m${text}\x1b[0m`;
}

export function emitSuccess(result, { json = false, noColor = false, progress } = {}, io = process) {
  const colorOpts = { noColor };
  if (json) {
    io.stdout.write(line(JSON.stringify(ok(result))));
    if (progress) io.stderr.write(line(progress));
    return;
  }
  if (progress) io.stderr.write(line(whiteVisible(progress, colorOpts, io)));
  if (result?.type === 'help' && typeof result.text === 'string') {
    io.stdout.write(whiteVisible(result.text, colorOpts, io));
  } else {
    io.stdout.write(line(whiteVisible(JSON.stringify(result), colorOpts, io)));
  }
}

export function emitError(error, { json = false, noColor = false } = {}, io = process) {
  if (json) {
    io.stdout.write(line(JSON.stringify(failEnvelope(error))));
    return;
  }
  const colorOpts = { noColor };
  const rawMsg = `error[${error.code}]: ${error.message}\n${error.hint ? `next: ${error.hint}\n` : ''}`;
  io.stderr.write(whiteVisible(rawMsg, colorOpts, io));
}
