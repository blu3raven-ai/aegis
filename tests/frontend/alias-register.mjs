// Registers the `@/` alias resolve hook for `node --test`. Wired in via the
// test:frontend script's `--import` flag so the loader thread sees it.
import { register } from "node:module"

register("./alias-hooks.mjs", import.meta.url)
