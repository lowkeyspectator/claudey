#!/usr/bin/env node
import { run } from '../src/cli/main.js';

process.exitCode = run();
