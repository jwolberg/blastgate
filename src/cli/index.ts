#!/usr/bin/env node
import { VERSION } from '../index';

function main(argv: string[]): number {
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`blastgate ${VERSION}\n`);
    return 0;
  }
  process.stdout.write(
    [
      `blastgate ${VERSION} — cross-layer attack-path gate`,
      '',
      'Usage:',
      '  blastgate [path]                 scan a repo for reachable attacker->sink paths',
      '  blastgate check --gate <phase>   plugin hook gate (reads hook JSON on stdin)',
      '  blastgate mcp                    stdio MCP self-check server',
      '',
      'Engine not yet implemented — this is the U1 scaffold.',
      '',
    ].join('\n'),
  );
  return 0;
}

process.exit(main(process.argv.slice(2)));
