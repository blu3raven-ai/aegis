// WHY: empty config prevents vite/vitest from crawling up to the root
// project's postcss.config.mjs which requires @tailwindcss/postcss.
export default { plugins: {} };
