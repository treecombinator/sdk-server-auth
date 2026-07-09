import { defineConfig } from "tsup";

// One entry. @treecombinator/sdk-common stays external (tsup externalizes deps).
// The email contract (`EmailMessage`) is imported as a type and INLINED into the
// declarations, so email remains a zero-runtime-dependency injection point.
// Portable dual ESM + CJS + type declarations.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: { resolve: ["@treecombinator/sdk-server-email"] },
  clean: true,
  sourcemap: true,
  target: "es2022",
  outDir: "dist",
});
