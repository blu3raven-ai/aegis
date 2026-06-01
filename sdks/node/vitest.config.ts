import { defineConfig } from "vitest/config";

export default defineConfig({
  // WHY: disable CSS processing entirely so vitest does not attempt to load
  // the root project's postcss.config.mjs (which requires @tailwindcss/postcss
  // not installed in this package).
  css: false,
  test: {
    environment: "node",
    include: ["__tests__/**/*.test.ts"],
  },
});
