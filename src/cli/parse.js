function usage(message) {
  const error = new Error(message);
  error.code = 'USAGE_ERROR';
  return error;
}

function requireValue(argv, index, option) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw usage(`${option} requires a value.`);
  return value;
}

function parsePort(value) {
  if (!/^\d+$/.test(value) || Number(value) < 1024 || Number(value) > 65535) {
    throw usage('PORT must be an integer from 1024 through 65535.');
  }
  return Number(value);
}

function parseVersion(value) {
  const normalized = value.startsWith('v') ? value.slice(1) : value;
  if (!/^\d+\.\d+\.\d+$/.test(normalized)) throw usage('VERSION must be a semantic version.');
  return normalized;
}

function setOption(options, key, value = true) {
  if (Object.hasOwn(options, key)) throw usage(`Duplicate option: ${key}.`);
  options[key] = value;
}

const globalOptions = new Map([
  ['--json', 'json'],
  ['--no-color', 'noColor'],
  ['--verbose', 'verbose'],
  ['--non-interactive', 'nonInteractive']
]);

function removeGlobalFlags(argv, options) {
  const remaining = [];
  for (const token of argv) {
    const key = globalOptions.get(token);
    if (key) setOption(options, key);
    else remaining.push(token);
  }
  return remaining;
}

function parseOptionList(argv, options, allowed) {
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw usage(`Unexpected operand: ${token}.`);
    if (!allowed.has(token)) throw usage(`Unknown option: ${token}.`);
    const { key, value } = allowed.get(token);
    if (value === 'port') {
      setOption(options, key, parsePort(requireValue(argv, index, token)));
      index += 1;
    } else if (value === 'version') {
      setOption(options, key, parseVersion(requireValue(argv, index, token)));
      index += 1;
    } else if (value === 'scope') {
      const scope = requireValue(argv, index, token);
      if (scope !== 'user' && scope !== 'local') throw usage('--scope must be user or local.');
      setOption(options, key, scope);
      index += 1;
    } else if (value === 'string') {
      setOption(options, key, requireValue(argv, index, token));
      index += 1;
    } else {
      setOption(options, key);
    }
  }
}

function flags(entries) {
  return new Map(entries.map(([token, key, value]) => [token, { key, value }]));
}

const optionSets = {
  setup: flags([['--version', 'version', 'version'], ['--port', 'port', 'port'], ['--with-cursor', 'withCursor'], ['--no-start', 'noStart'], ['--no-path', 'noPath'], ['--yes', 'yes']]),
  install: flags([['--version', 'version', 'version'], ['--port', 'port', 'port'], ['--yes', 'yes']]),
  authCodex: flags([['--device-code', 'deviceCode'], ['--no-browser', 'noBrowser'], ['--callback-port', 'callbackPort', 'port']]),
  authAntigravity: flags([['--no-browser', 'noBrowser'], ['--callback-port', 'callbackPort', 'port']]),
  start: flags([['--foreground', 'foreground']]),
  update: flags([['--check', 'check'], ['--version', 'version', 'version'], ['--yes', 'yes']]),
  rollback: flags([['--version', 'version', 'version'], ['--yes', 'yes']]),
  cursorScope: flags([['--scope', 'scope', 'scope']]),
  cursorInstall: flags([['--yes', 'yes']]),
  cursorWritesEnable: flags([['--yes', 'yes']]),
  cursorMcpServe: flags([
    ['--source-root', 'sourceRoot', 'string'], ['--installation-id', 'installationId', 'string'],
    ['--manager-root', 'managerRoot', 'string']
  ]),
  uninstall: flags([['--dry-run', 'dryRun'], ['--purge-auth', 'purgeAuth'], ['--yes', 'yes']])
};

function assertNoMutuallyExclusive(options, first, second) {
  if (options[first] && options[second]) throw usage(`Options ${first} and ${second} cannot be used together.`);
}

const MANAGEMENT_COMMANDS = new Set([
  'onboard', 'setup', 'install', 'auth', 'start', 'stop', 'restart', 'status', 'doctor',
  'update', 'rollback', 'models', 'config', 'cursor', 'uninstall'
]);

function asClaudeyLaunch(rawArgv) {
  return { command: ['launcher', 'claudey'], options: { rawArgv } };
}

export function parseManagementArgs(argv, environment = process.env) {
  const options = {};
  let tokens = removeGlobalFlags([...argv], options);
  if (environment.CI === 'true') options.nonInteractive = true;
  if (tokens[0] === 'launcher' && tokens[1] === 'claudey') {
    const rest = tokens.slice(2);
    if (!rest[0] || rest[0].startsWith('--') || !MANAGEMENT_COMMANDS.has(rest[0])) return asClaudeyLaunch(rest);
    tokens = rest;
  } else if (!tokens[0] || tokens[0].startsWith('--')) {
    return asClaudeyLaunch(tokens);
  }
  const [first, second, third] = tokens;

  const consume = (count, allowed) => parseOptionList(tokens.slice(count), options, allowed);
  if (first === 'launcher') {
    if (!second || !['claudey', 'claudeyctl', 'claude-codex', 'claude-agy', 'claude-grok'].includes(second)) throw usage('launcher requires claudey, claude-codex, claude-agy, or claude-grok.');
    return { command: ['launcher', second], options: { rawArgv: tokens.slice(2) } };
  }
  if (first === 'onboard') consume(1, optionSets.setup);
  else if (first === 'setup') consume(1, optionSets.setup);
  else if (first === 'install') consume(1, optionSets.install);
  else if (first === 'start') consume(1, optionSets.start);
  else if (first === 'stop' || first === 'restart' || first === 'status' || first === 'doctor') consume(1, new Map());
  else if (first === 'update') {
    consume(1, optionSets.update);
    assertNoMutuallyExclusive(options, 'check', 'version');
    if (options.check && options.yes) throw usage('--yes is not allowed with update --check.');
  } else if (first === 'rollback') consume(1, optionSets.rollback);
  else if (first === 'uninstall') consume(1, optionSets.uninstall);
  else if (first === 'models') {
    if (tokens.length > 2 || (second && !['codex', 'antigravity', 'grok', 'cursor', 'all'].includes(second))) throw usage('models accepts codex, antigravity, grok, cursor, or all.');
    return { command: second ? ['models', second] : ['models'], options };
  } else if (first === 'auth') {
    if (!['codex', 'antigravity', 'grok', 'all'].includes(second)) {
      throw usage('auth requires grok, antigravity, codex, or all.');
    }
    consume(2, second === 'antigravity' ? optionSets.authAntigravity : optionSets.authCodex);
    assertNoMutuallyExclusive(options, 'deviceCode', 'noBrowser');
    return { command: ['auth', second], options };
  } else if (first === 'config') {
    if (second !== 'set' || third !== 'port') throw usage('Expected config set port PORT.');
    const port = tokens[3];
    if (port === undefined || port.startsWith('--')) throw usage('config set port requires PORT.');
    setOption(options, 'port', parsePort(port));
    parseOptionList(tokens.slice(4), options, flags([['--yes', 'yes']]));
    return { command: ['config', 'set', 'port'], options };
  } else if (first === 'cursor') {
    if (second === 'enable' || second === 'disable') {
      consume(2, optionSets.cursorScope);
      if (!options.scope) throw usage(`${second} requires --scope user or --scope local.`);
      return { command: ['cursor', second], options };
    }
    if (second === 'install') { consume(2, optionSets.cursorInstall); return { command: ['cursor', 'install'], options }; }
    if (second === 'login') { consume(2, new Map()); return { command: ['cursor', 'login'], options }; }
    if (second === 'mcp-serve') {
      consume(2, optionSets.cursorMcpServe);
      if (!options.installationId || !options.managerRoot) throw usage('cursor mcp-serve requires installation and manager identities.');
      return { command: ['cursor', 'mcp-serve'], options };
    }
    if (second === 'approve') {
      const approvalId = tokens[2];
      if (!approvalId || approvalId.startsWith('--')) throw usage('cursor approve requires APPROVAL_ID.');
      setOption(options, 'approvalId', approvalId);
      parseOptionList(tokens.slice(3), options, new Map());
      return { command: ['cursor', 'approve'], options };
    }
    if (second === 'writes') {
      if (third === 'enable') {
        consume(3, optionSets.cursorWritesEnable);
        if (!options.yes) throw usage('cursor writes enable requires --yes.');
      } else if (third === 'disable') consume(3, new Map());
      else throw usage('cursor writes requires enable or disable.');
      return { command: ['cursor', 'writes', third], options };
    }
    if (second === 'repo') {
      if (!['add', 'list', 'remove'].includes(third)) throw usage('cursor repo requires add, list, or remove.');
      const operands = tokens.slice(3);
      let selectedPath;
      for (const operand of operands) {
        if (operand === '--yes') setOption(options, 'yes');
        else if (operand.startsWith('--')) throw usage(`Unknown option: ${operand}.`);
        else if (selectedPath !== undefined) throw usage(`cursor repo ${third} accepts at most one PATH.`);
        else selectedPath = operand;
      }
      const path = selectedPath;
      if (third === 'list' && path !== undefined) throw usage('cursor repo list accepts no path.');
      if (third === 'list' && options.yes) throw usage('cursor repo list accepts no confirmation.');
      if ((third === 'add' || third === 'remove') && path !== undefined) setOption(options, 'path', path);
      return { command: ['cursor', 'repo', third], options };
    }
    throw usage('Unknown cursor command.');
  } else throw usage(`Unknown command: ${first}.`);

  return { command: [first], options };
}

export function parseLauncherArgs(argv, environment = process.env) {
  const delimiter = argv.indexOf('--');
  const before = delimiter === -1 ? argv : argv.slice(0, delimiter);
  const claudeArgs = delimiter === -1 ? [] : argv.slice(delimiter + 1);
  const result = { model: undefined, select: false, all: false, claudeArgs, nonInteractive: environment.CI === 'true' };
  let yolo = false;
  for (let index = 0; index < before.length; index += 1) {
    const token = before[index];
    if (token === '--model') {
      if (result.model !== undefined) throw usage('Duplicate option: --model.');
      result.model = requireValue(before, index, token);
      index += 1;
    } else if (token === '--select') {
      if (result.select) throw usage('Duplicate option: --select.');
      result.select = true;
    } else if (token === '--all') {
      if (result.all) throw usage('Duplicate option: --all.');
      result.all = true;
    } else if (token === '--yolo') {
      if (yolo) throw usage('Duplicate option: --yolo.');
      yolo = true;
    } else if (globalOptions.has(token)) {
      if (delimiter !== -1) throw usage('Global flags are not accepted by launchers.');
      if (token === '--non-interactive') result.nonInteractive = true;
      else throw usage('Global flags are not accepted by launchers.');
    } else throw usage(`Unknown launcher option: ${token}.`);
  }
  if (result.model !== undefined && result.select) throw usage('--model and --select cannot be used together.');
  if (yolo && !result.claudeArgs.includes('--dangerously-skip-permissions')) {
    result.claudeArgs = ['--dangerously-skip-permissions', ...result.claudeArgs];
  }
  return result;
}
