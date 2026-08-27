import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  globalIgnores([
    "node_modules/**",
    "dist/**",
    "packages/sdk/dist/**",
    "packages/gated-deploy/dist/**",
    "packages/mcp-proxy/dist/**",
    "worker-configuration.d.ts",
  ]),
  {
    files: ["**/*.{js,mjs,ts}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
  },
  // The Worker runs in workerd, where `process` and `console` as Node globals
  // are not a given; scripts/ runs in Node and is not bundled. Scoping the
  // globals rather than declaring them everywhere keeps the Worker honest about
  // what it may reach for.
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      globals: {
        URL: "readonly",
        console: "readonly",
        process: "readonly",
      },
    },
  },
);
