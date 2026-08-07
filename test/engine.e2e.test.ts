import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeProvenance } from '../src/analyzers/deps/provenance';
import { collectInputs, type RepoFs } from '../src/cli/collect';
import { type GateResult, runEngine } from '../src/engine/gate';
import { cachedFetcher, type Packument } from '../src/registry/packument';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

/**
 * A `RepoFs` over a static fixture directory. `git show <ref>:package-lock.json`
 * is served from a committed `package-lock.base.json` — so diff-based checks work
 * without a git repo per fixture.
 */
function fixtureFs(dir: string): RepoFs {
  return {
    read: (rel) => {
      try {
        return readFileSync(join(dir, rel), 'utf8');
      } catch {
        return null;
      }
    },
    listWorkflows: () => {
      const wfDir = join(dir, '.github', 'workflows');
      try {
        return readdirSync(wfDir)
          .filter((f) => /\.ya?ml$/.test(f))
          .map((f) => `.github/workflows/${f}`);
      } catch {
        return [];
      }
    },
    // The base ref is a committed `<path>.base` sidecar (the lockfile keeps its
    // historical `package-lock.base.json` name); absent sidecar ⇒ new at head.
    gitShow: (_ref, rel) => {
      const sidecar = rel === 'package-lock.json' ? 'package-lock.base.json' : `${rel}.base`;
      try {
        return readFileSync(join(dir, sidecar), 'utf8');
      } catch {
        return null;
      }
    },
  };
}

/** Run the full engine over a fixture dir; inject recorded packuments if present (provenance). */
async function runFixture(dir: string): Promise<GateResult> {
  const fs = fixtureFs(dir);
  const inputs = collectInputs(fs, { base: 'BASE' });

  const packumentsRaw = fs.read('packuments.json');
  if (packumentsRaw) {
    const recorded = JSON.parse(packumentsRaw) as Record<string, Packument | null>;
    const source = { fetch: (pkg: string) => Promise.resolve(recorded[pkg] ?? null) };
    const headLock = fs.read('package-lock.json');
    const baseLock = fs.gitShow ? fs.gitShow('BASE', 'package-lock.json') : null;
    if (headLock) {
      inputs.provenance = await analyzeProvenance(baseLock, headLock, cachedFetcher(source));
    }
  }
  return runEngine(inputs);
}

interface CheckSpec {
  name: string;
  /** The verdict the positive fixture must produce (fail for secret paths, warn for capability). */
  positiveVerdict: 'fail' | 'warn';
  /** Extra assertions on the positive result (path / label). */
  assertPositive?: (result: GateResult) => void;
}

const CHECKS: CheckSpec[] = [
  {
    name: 'install-script-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'new-dependency');
      expect(f, 'a new-dependency (install-script) finding').toBeDefined();
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI04:2026');
      expect(f!.labels).toContain('MCP04:2025');
    },
  },
  {
    name: 'fork-pr-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'fork-pr');
      expect(f, 'a fork-pr finding').toBeDefined();
      expect(f!.sink.kind === 'secret' || f!.sink.kind === 'credential').toBe(true);
      expect(f!.labels).toContain('ASI03:2026');
    },
  },
  {
    name: 'agent-overprivilege',
    positiveVerdict: 'warn',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.sink.kind === 'privileged-capability');
      expect(f, 'a capability finding').toBeDefined();
      expect(f!.tier).toBe('warn');
      expect(f!.labels).toContain('MCP02:2025');
    },
  },
  {
    name: 'provenance-regression',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.pathNodeIds[0] === 'entry:provenance:evil-pkg');
      expect(f, 'a provenance-regression finding').toBeDefined();
      expect(f!.tier).toBe('fail');
    },
  },
  {
    name: 'ci-divergent-install',
    positiveVerdict: 'warn',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'ci-divergent');
      expect(f, 'a ci-divergent finding').toBeDefined();
      expect(f!.tier).toBe('warn');
      expect(f!.sink.kind).toBe('privileged-capability');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
  {
    name: 'untrusted-text-injection',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'untrusted-text-injection');
      expect(f, 'an untrusted-text-injection finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.labels).toContain('ASI01:2026');
    },
  },
  {
    // 0042: a workflow_run job splicing a downloaded (untrusted) artifact into a shell.
    name: 'ci-artifact-injection',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'untrusted-text-injection');
      expect(f, 'a workflow_run artifact-injection finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.entry.label).toContain('artifact');
    },
  },
  {
    name: 'agent-config-injection',
    positiveVerdict: 'warn',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'agent-config-change');
      expect(f, 'an agent-config-change finding').toBeDefined();
      expect(f!.tier).toBe('warn');
      expect(f!.labels).toContain('ASI01:2026');
    },
  },
  {
    name: 'gate-tamper',
    positiveVerdict: 'warn',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.entry.kind === 'gate-tamper');
      expect(f, 'a gate-tamper finding').toBeDefined();
      expect(f!.tier).toBe('warn');
    },
  },
  {
    name: 'python-install-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.pathNodeIds.includes('dep:python:setup.py'));
      expect(f, 'a Python install-time → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
  {
    name: 'rubygems-install-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.pathNodeIds.some((id) => id.startsWith('dep:ruby:')));
      expect(f, 'a RubyGems install → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
  {
    name: 'pypi-dep-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) =>
        x.pathNodeIds.some((id) => id.startsWith('dep:python:pkg:')),
      );
      expect(f, 'a PyPI dependency → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
  {
    name: 'gitlab-fork-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find((x) => x.pathNodeIds.some((id) => id.startsWith('entry:fork-mr:')));
      expect(f, 'a GitLab merge-request → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI03:2026');
    },
  },
  {
    // 0040: a yarn.lock repo — an added dep installed by a fork-triggerable job → secret.
    name: 'yarn-install-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find(
        (x) => x.entry.kind === 'new-dependency' && x.pathNodeIds.includes('dep:evil-pkg@2.0.0'),
      );
      expect(f, 'a yarn added-dep → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
  {
    // 0040: the same shape for a pnpm-lock.yaml repo.
    name: 'pnpm-install-secret',
    positiveVerdict: 'fail',
    assertPositive: (r) => {
      const f = r.findings.find(
        (x) => x.entry.kind === 'new-dependency' && x.pathNodeIds.includes('dep:evil-pkg@2.0.0'),
      );
      expect(f, 'a pnpm added-dep → secret finding').toBeDefined();
      expect(f!.tier).toBe('fail');
      expect(f!.sink.identity).toBe('AWS_SECRET_ACCESS_KEY');
      expect(f!.labels).toContain('ASI04:2026');
    },
  },
];

describe('engine e2e over fixture repos (R13)', () => {
  it('coverage: on-disk fixtures are exactly the declared checks, each with a positive+negative pair', () => {
    const onDisk = readdirSync(FIXTURES).filter((d) => statSync(join(FIXTURES, d)).isDirectory());
    // A check with no fixtures, or a fixture dir with no declared check, fails here.
    expect(new Set(onDisk)).toEqual(new Set(CHECKS.map((c) => c.name)));
    for (const check of CHECKS) {
      expect(existsSync(join(FIXTURES, check.name, 'positive')), `${check.name}/positive`).toBe(
        true,
      );
      expect(existsSync(join(FIXTURES, check.name, 'negative')), `${check.name}/negative`).toBe(
        true,
      );
    }
  });

  for (const check of CHECKS) {
    it(`${check.name}: positive fixture → ${check.positiveVerdict} (true positive)`, async () => {
      const result = await runFixture(join(FIXTURES, check.name, 'positive'));
      expect(result.verdict).toBe(check.positiveVerdict);
      check.assertPositive?.(result);
    });

    it(`${check.name}: negative fixture → pass (true negative, R14)`, async () => {
      const result = await runFixture(join(FIXTURES, check.name, 'negative'));
      expect(result.verdict).toBe('pass');
      expect(result.findings).toHaveLength(0);
    });
  }
});
