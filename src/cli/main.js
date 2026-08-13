import { parseManagementArgs } from './parse.js';

export function main(argv = process.argv.slice(2), environment = process.env) {
  return parseManagementArgs(argv, environment);
}
