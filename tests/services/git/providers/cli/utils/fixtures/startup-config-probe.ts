/**
 * @fileoverview Harmless startup-configuration provenance probe for G2 diagnosis.
 * @module tests/services/git/providers/cli/utils/fixtures/startup-config-probe
 */
import { config } from '@/config/index.js';
process.stdout.write(
  JSON.stringify({
    profile: config.git.executionProfile,
    binaryPath: config.git.binaryPath,
    trustedHome: config.git.trustedHome,
    runtime: process.versions.bun ? 'bun' : 'node',
    roots: config.git.baseDirs,
    preloadMarker:
      (globalThis as { startupFixturePreloaded?: boolean })
        .startupFixturePreloaded ?? false,
    execArgv: process.execArgv,
  }) + '\n',
);
