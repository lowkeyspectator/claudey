import { failEnvelope, ok } from '../core/result.js';

function line(value) {
  return `${value}\n`;
}

export function emitSuccess(result, { json = false, progress } = {}, io = process) {
  if (json) {
    io.stdout.write(line(JSON.stringify(ok(result))));
    if (progress) io.stderr.write(line(progress));
    return;
  }
  if (progress) io.stderr.write(line(progress));
  if (result?.type === 'help' && typeof result.text === 'string') io.stdout.write(result.text);
  else io.stdout.write(line(JSON.stringify(result)));
}

export function emitError(error, { json = false } = {}, io = process) {
  if (json) {
    io.stdout.write(line(JSON.stringify(failEnvelope(error))));
    return;
  }
  io.stderr.write(`error[${error.code}]: ${error.message}\n${error.hint ? `next: ${error.hint}\n` : ''}`);
}
