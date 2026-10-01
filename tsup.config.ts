import { defineConfig } from 'tsup';

export default defineConfig({
  // src/crawl/index.ts is internal ops tooling (KTD9): built, but excluded from the npm package
  // by the negated `files` pattern in package.json.
  entry: ['src/index.ts', 'src/cli/index.ts', 'src/action/index.ts', 'src/crawl/index.ts'],
  format: ['esm'],
  target: 'node20',
  outDir: 'dist',
  clean: true,
  dts: false,
  sourcemap: true,
});
