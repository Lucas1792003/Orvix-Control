import { defineConfig } from "vitest/config";

// W-1 crash injection: kills PostgreSQL backends (whole-cluster restart). Disposable clusters only; see tests/crash.
export default defineConfig({
  test: {
    include: ["tests/crash/**/*.test.ts"],
    testTimeout: 90_000,
    hookTimeout: 90_000,
    fileParallelism: false,
  },
});
