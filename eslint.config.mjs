import eslint from "@eslint/js";
import { defineConfig } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig({
  extends: [eslint.configs.recommended, tseslint.configs.recommended],
  files: ["**/*.{ts}"],
  languageOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    globals: globals.node,
    parserOptions: {
      parser: tseslint.parser,
    },
  },
  // 0 off 1 warn 2 error
  rules: {
    "@typescript-eslint/ban-ts-comment": 0,
    quotes: [2, "double"],
    semi: [2, "always"],
    "no-console": 0,
  },
  ignores: ["node_modules/*", "dist/*", "build"],
});
