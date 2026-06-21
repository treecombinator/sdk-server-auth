import { defineConfig } from "tsup";

// One entry. @treecombinator/sdk-common stays external (tsup externalizes deps).
// Portable dual ESM + CJS + type declarations.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "es2022",
  outDir: "dist",
});
