import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  globalIgnores([
    "node_modules/**",
    "dist/**",
    "packages/sdk/dist/**",
    "worker-configuration.d.ts",
  ]),
  {
    files: ["**/*.{js,mjs,ts}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
  },
);
