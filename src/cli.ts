#!/usr/bin/env node

import { cwd } from 'node:process';
import { runInit } from './commands/init.js';
import { runSign } from './commands/sign.js';
import { runVerify } from './commands/verify.js';
import { runScope } from './commands/scope.js';

const argv = process.argv.slice(2);
const cmd = argv[0];

switch (cmd) {
  case 'init':
    runInit(cwd());
    break;
  case 'sign':
    runSign(cwd());
    break;
  case 'verify':
    runVerify(cwd());
    break;
  case 'scope':
    runScope(cwd());
    break;
  case undefined:
  case '-h':
  case '--help':
    console.log(`nxtlinq-attest - nxtlinq attest CLI

Usage: nxtlinq-attest <command>

Commands:
  init     Initialize nxtlinq/ (keys and agent.manifest.json)
  sign     Sign manifest and artifact, write nxtlinq/agent.manifest.sig
  verify   Verify manifest and artifact integrity (exit 1 on failure)
  scope    Print manifest scope as JSON to stdout (for any runtime to call)

Options:
  -h, --help  Show this help.
`);
    break;
  default:
    console.error('Unknown command:', cmd);
    console.error('Run "nxtlinq-attest --help" for usage.');
    process.exit(1);
}
