// ESM resolve hook so `node --test` can resolve the `@/` path alias used across
// the frontend (mirrors the `@/*` -> `frontend/*` mapping in tsconfig). Without
// it, any test that imports a module which (transitively) uses `@/` fails with
// ERR_MODULE_NOT_FOUND. Registered via tests/frontend/alias-register.mjs.
import { existsSync } from "node:fs"
import { dirname, resolve as resolvePath } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const FRONTEND_ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), "..", "..", "frontend")
const EXTS = [".ts", ".tsx", ".mts", ".js", ".mjs", ".jsx", ".json"]

function resolveAliasTarget(subpath) {
  const base = resolvePath(FRONTEND_ROOT, subpath)
  if (existsSync(base) && !EXTS.some((e) => base.endsWith(e))) {
    // Directory import -> look for an index file.
    for (const ext of EXTS) {
      const idx = resolvePath(base, `index${ext}`)
      if (existsSync(idx)) return idx
    }
  }
  if (existsSync(base)) return base
  for (const ext of EXTS) {
    if (existsSync(base + ext)) return base + ext
  }
  for (const ext of EXTS) {
    const idx = resolvePath(base, `index${ext}`)
    if (existsSync(idx)) return idx
  }
  return base
}

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith("@/")) {
    const target = resolveAliasTarget(specifier.slice(2))
    return nextResolve(pathToFileURL(target).href, context)
  }
  return nextResolve(specifier, context)
}
