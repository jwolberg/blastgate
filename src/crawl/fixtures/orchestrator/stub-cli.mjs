// Stub Blastgate CLI for src/crawl/index.test.ts. The scanned repo's package.json `name`
// picks the behavior: `fail` emits one full, real-shaped fail finding WITH a payload (so the
// tests can prove it never leaves the scan job); anything else is a clean pass.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.argv[2] === '--version') {
  process.stdout.write('blastgate 9.9.9\n');
  process.exit(0);
}
const dir = path.dirname(fileURLToPath(import.meta.url));
const real = JSON.parse(fs.readFileSync(path.join(dir, '..', 'disclose', 'real-fails.json'), 'utf8'));
const template = Object.values(real)[0][0];
let mode = 'pass';
try {
  mode = JSON.parse(fs.readFileSync(path.join(process.argv[2], 'package.json'), 'utf8')).name;
} catch {
  /* no package.json: pass */
}
if (mode === 'fail') {
  const f = { ...template, evidence: { ...template.evidence, payload: 'PAYLOAD-SECRET-TEXT' } };
  process.stdout.write(JSON.stringify([f]));
} else {
  process.stdout.write('[]');
}
