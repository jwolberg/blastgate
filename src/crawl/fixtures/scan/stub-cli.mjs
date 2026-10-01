// Stub Blastgate CLI for src/crawl/scan.test.ts. Behavior is chosen by the scanned repo's
// package.json `name` (the only file besides .github/ the sparse clone checks out).
import fs from 'node:fs';
import path from 'node:path';

if (process.argv[2] === '--version') {
  process.stdout.write('blastgate 9.9.9\n');
  process.exit(0);
}
const dir = process.argv[2];
let mode = 'pass';
try {
  mode = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).name;
} catch {
  /* no package.json: pass */
}
const finding = (tier, id) => ({
  id,
  tier,
  entry: { kind: 'pull_request_target', label: 'PR title' },
  sink: { kind: 'agent', identity: 'claude-code-action' },
  evidence: {
    file: '.github/workflows/ci.yml',
    line: 3,
    capability: 'GITHUB_TOKEN',
    payload: 'PAYLOAD-SECRET-TEXT',
  },
});
const out = (v) => process.stdout.write(JSON.stringify(v));
switch (mode) {
  case 'warn':
    out([finding('warn', 'e1=>s1')]);
    break;
  case 'fail':
    out([finding('warn', 'e1=>s1'), finding('fail', 'e2=>s2')]);
    break;
  case 'exit1':
    out([finding('warn', 'e1=>s1')]);
    process.exit(1);
    break;
  case 'exit1-clean':
    out([]);
    process.exit(1);
    break;
  case 'exit2':
    process.exit(2);
    break;
  case 'hang':
    setTimeout(() => {}, 60_000);
    break;
  case 'garbage':
    process.stdout.write('{not json');
    break;
  default:
    out([]);
}
