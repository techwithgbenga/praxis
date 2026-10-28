// SPDX-License-Identifier: Apache-2.0
// AGENTS.md §5: TypeScript strict mode, ESM, no `any`.
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "eslint.config.mjs"],
  },
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/explicit-function-return-type": "error",
    },
  },
  {
    // `node:test`'s `test()` returns a Promise the runner awaits internally;
    // treating that as a floating promise in every single test file would
    // just be noise.
    files: ["**/*.test.ts"],
    rules: {
      "@typescript-eslint/no-floating-promises": "off",
    },
  },
);
