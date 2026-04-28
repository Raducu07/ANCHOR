import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Nested Claude worktrees include their own Next.js builds and source trees.
    // Lint each worktree from inside its own directory; never let a parent-repo
    // lint pass crawl into them.
    ".claude/**",
  ]),
]);

export default eslintConfig;
