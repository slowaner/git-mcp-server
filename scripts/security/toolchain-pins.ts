/**
 * @fileoverview Reviewed CI and publisher inputs; verify archive SHA-256 before use.
 * @module scripts/security/toolchain-pins
 * @see https://github.com/oven-sh/bun/releases/tag/bun-v1.4.3
 * @see https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
 * @see https://github.com/modelcontextprotocol/registry/releases/tag/v1.8.7
 */

/** Pins verified against primary GitHub release metadata on 2026-11-03. */
export const TOOLCHAIN_PINS = {
  schema: {
    url: 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',
    sourceSha256:
      '3fba09590c99f61735d234822279f4223fab9e300c0a81e81c91ab62a4114de0',
    sha256: '8ca42989ecdbce74f5bd0301f3db4cc760e6ad8d1054d44734a24ed0f977f998',
  },
  bun: {
    version: '1.4.3',
    commit: 'c6da4a4d3010e5553438c60f6bd76d981976867c',
    linuxX64: {
      url: 'https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-linux-x64.zip',
      sha256:
        '3e730528d89775f03f87f05c06787c4df4099d0a37f3f252e7b829cb23816e18',
    },
    darwinArm64: {
      url: 'https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-darwin-aarch64.zip',
      sha256:
        '80afd4c069b46a6fa8f3ec520bebc750a7843e4a8d5b9583d29ad436c00a3403',
    },
  },
  gitleaks: {
    version: '8.30.1',
    rulesSha256:
      'e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf',
    rulesBytes: 97731,
    rulesGitBlob: '256f64790ea6d954f0041024be2938089ae1e7a7',
    emptyIgnoreSha256:
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    rulesUrl:
      'https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml',
    linuxX64: {
      url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
      sha256:
        '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
    },
    darwinArm64: {
      url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz',
      sha256:
        'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
    },
  },
  publisher: {
    version: '1.8.7',
    commit: '741d575fc2ffe774fa51f442ec6fb2987dd03e18',
    linuxX64: {
      url: 'https://github.com/modelcontextprotocol/registry/releases/download/v1.8.7/mcp-publisher_linux_amd64.tar.gz',
      sha256:
        '00b21004149a4ce66f0782508ae4a2bce67d1bea395a8da0bd8028159fb59579',
    },
    darwinArm64: {
      url: 'https://github.com/modelcontextprotocol/registry/releases/download/v1.8.7/mcp-publisher_darwin_arm64.tar.gz',
      sha256:
        'b63dc083beb27e1a44c07c252ac147ff2c34af2f7822f705a17f8d0e1b44d592',
    },
  },
  actions: {
    checkout: '34e114876b0b11c390a56381ad16ebd13914f8d5', // v4.3.1
    codeql: '9b3254085494b55a0f7c4c2b3d2d52cc712ce370', // v4 tag dereferenced
  },
  codeql: {
    version: '2.27.4',
    linuxX64: {
      url: 'https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-linux64.tar.gz',
      sha256:
        '89ed56c8ec6bfccef6a0d2e7fe86da0469ca24b4db08b88016ec134b942c17a4',
    },
  },
} as const;
