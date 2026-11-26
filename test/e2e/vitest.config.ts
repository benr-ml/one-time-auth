import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

export default defineConfig({
	root: fileURLToPath(new URL('../..', import.meta.url)),
	test: {
		include: ['test/e2e/**/*.test.ts'],
		globalSetup: ['test/e2e/globalSetup.ts'],
		fileParallelism: false,
		testTimeout: 120_000,
		hookTimeout: 180_000,
	},
});
