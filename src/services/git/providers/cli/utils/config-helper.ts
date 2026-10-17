/**
 * @fileoverview Helper utilities for loading git configuration
 * @module services/git/providers/cli/utils/config-helper
 */

import type { AppConfig } from '@/config/index.js';

/**
 * Safely load the application config.
 * Uses dynamic require to avoid circular dependencies.
 *
 * @returns AppConfig object or null if unavailable
 */
export function loadConfig(): AppConfig | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const configModule = require('@/config/index.js') as {
      config: AppConfig;
    };
    return configModule.config;
  } catch {
    return null;
  }
}

/**
 * Whether to explicitly request signing for commits, tags, merges, rebases,
 * cherry-picks, and pulls. False leaves native Git signing configuration in
 * control; it does not disable signing. Commit/tag creation alone retries a
 * failed explicit request without the signing flag. Results report actual
 * signature presence and expose the retry through `signingWarning`.
 * Returns false if config is unavailable.
 */
export function shouldSignCommits(): boolean {
  return loadConfig()?.git?.signCommits ?? false;
}
