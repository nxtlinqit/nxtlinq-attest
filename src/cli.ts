#!/usr/bin/env node

import { cwd } from 'node:process';
import { runInit } from './commands/init.js';
import { runSign } from './commands/sign.js';
import { runVerify } from './commands/verify.js';
import { runScope } from './commands/scope.js';
import { getCliVersion } from './lib/version.js';

const argv = process.argv.slice(2);
const cmd = argv[0];

function parseInitOptions(args: string[]): { publicKeyPath?: string; keyId?: string } {
  const options: { publicKeyPath?: string; keyId?: string } = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--public-key' || arg === '--key-id') {
      const value = args[index + 1];
      if (!value) throw new Error(`${arg} requires a value`);
      if (arg === '--public-key') options.publicKeyPath = value;
      else options.keyId = value;
      index += 1;
    } else {
      throw new Error(`Unknown init option: ${arg}`);
    }
  }
  return options;
}

function parseSignOptions(args: string[]): { privateKeyPath?: string } {
  const options: { privateKeyPath?: string } = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--private-key') {
      const value = args[index + 1];
      if (!value) throw new Error('--private-key requires a path');
      options.privateKeyPath = value;
      index += 1;
    } else {
      throw new Error(`Unknown sign option: ${arg}`);
    }
  }
  return options;
}

function parseVerifyOptions(args: string[]): { trustStorePath?: string; expectedAudience?: string } {
  const options: { trustStorePath?: string; expectedAudience?: string } = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--trust-store') {
      const value = args[index + 1];
      if (!value) throw new Error('--trust-store requires a path');
      options.trustStorePath = value;
      index += 1;
    } else if (arg === '--audience') {
      const value = args[index + 1];
      if (!value) throw new Error('--audience requires a value');
      options.expectedAudience = value;
      index += 1;
    } else {
      throw new Error(`Unknown verify option: ${arg}`);
    }
  }
  return options;
}

try {
  switch (cmd) {
    case '-v':
    case '--version':
      console.log(getCliVersion());
      break;
    case 'init':
      runInit(cwd(), parseInitOptions(argv.slice(1)));
      break;
    case 'sign':
      await runSign(cwd(), parseSignOptions(argv.slice(1)));
      break;
    case 'verify':
      runVerify(cwd(), parseVerifyOptions(argv.slice(1)));
      break;
    case 'scope':
      runScope(cwd());
      break;
    case undefined:
    case '-h':
    case '--help':
      console.log(`nxtlinq-attest - nxtlinq attest CLI

Usage: nxtlinq-attest <command> [options]

Commands:
  init     Initialize nxtlinq/ (keys and agent.manifest.json)
  sign     Sign manifest and artifact, write nxtlinq/agent.manifest.sig
  verify   Verify manifest and artifact integrity (exit 1 on failure)
  scope    Print manifest scope as JSON to stdout (for any runtime to call)

Options:
  -h, --help     Show this help.
  -v, --version  Print CLI version and exit.

Verify options:
  --trust-store <path>  Require a signer listed in the external trust store.
  --audience <value>    Require the signed manifest audience to match.

Sign options:
  --private-key <path>  Sign with a private key stored outside the project.

Init options:
  --public-key <path>  Initialize without creating a project-local private key.
  --key-id <value>     Operational key identity; required with --public-key.
`);
      break;
    default:
      console.error('Unknown command:', cmd);
      console.error('Run "nxtlinq-attest --help" for usage.');
      process.exit(1);
  }
} catch (error) {
  console.error('Error:', error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
