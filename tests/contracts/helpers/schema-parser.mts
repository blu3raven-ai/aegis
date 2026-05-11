import { readFileSync } from "node:fs"
import path from "node:path"

const ROOT = path.resolve(import.meta.dirname, "../../..")

/** Convert snake_case to camelCase. */
export function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
}

/**
 * Extract field names from a Strawberry @strawberry.type class.
 * Returns an array of snake_case field names.
 */
export function extractStrawberryFields(filePath: string, className: string): string[] {
  const source = readFileSync(path.join(ROOT, filePath), "utf-8")
  const classRegex = new RegExp(
    `@strawberry\\.type\\s*\\nclass\\s+${className}[^:]*:\\n((?:[ \\t]+[^\\n]+\\n)*)`,
    "m"
  )
  const match = source.match(classRegex)
  if (!match) throw new Error(`Class ${className} not found in ${filePath}`)

  const body = match[1]
  const fields: string[] = []
  for (const line of body.split("\n")) {
    const fieldMatch = line.match(/^\s+(\w+)\s*:/)
    if (fieldMatch && !fieldMatch[1].startsWith("_")) {
      fields.push(fieldMatch[1])
    }
  }
  return fields
}

/**
 * Extract function parameter names from a Python def signature.
 * Returns snake_case param names (excludes self, info, info_context).
 */
export function extractResolverParams(filePath: string, funcName: string): string[] {
  const source = readFileSync(path.join(ROOT, filePath), "utf-8")
  // Match the full function signature (may span multiple lines)
  const funcRegex = new RegExp(`def\\s+${funcName}\\s*\\(([^)]+)\\)`, "s")
  const match = source.match(funcRegex)
  if (!match) throw new Error(`Function ${funcName} not found in ${filePath}`)

  const params = match[1]
  const ignored = new Set(["self", "info", "info_context", "org"])
  return params
    .split(",")
    .map((p) => p.trim().split(":")[0].trim().split("=")[0].trim())
    .filter((p) => p && !ignored.has(p))
}

/**
 * Extract field names from a GraphQL query selection set (top-level items fields).
 * Returns camelCase field names.
 */
export function extractQueryFields(queryString: string, selectionPath: string): string[] {
  // Find the selection set for the given path (e.g., "secretFindings.items")
  const parts = selectionPath.split(".")
  let source = queryString

  for (const part of parts) {
    const idx = source.indexOf(part)
    if (idx === -1) throw new Error(`Selection "${part}" not found in query`)
    source = source.slice(idx)
    // Find the opening brace
    const braceIdx = source.indexOf("{")
    if (braceIdx === -1) throw new Error(`No selection set for "${part}"`)
    source = source.slice(braceIdx + 1)
  }

  // Extract fields until closing brace (handling nesting)
  const fields: string[] = []
  let depth = 1
  let i = 0
  let currentField = ""

  while (i < source.length && depth > 0) {
    const ch = source[i]
    if (ch === "{") {
      depth++
      // Skip nested selection set
      currentField = ""
    } else if (ch === "}") {
      depth--
      if (depth === 0) break
      currentField = ""
    } else if (/\s/.test(ch)) {
      if (currentField && depth === 1) {
        fields.push(currentField)
      }
      currentField = ""
    } else if (depth === 1) {
      currentField += ch
    }
    i++
  }
  if (currentField && depth <= 1) fields.push(currentField)

  return fields.filter((f) => f.length > 0 && /^[a-zA-Z]/.test(f))
}

/**
 * Extract GraphQL query variable names (parameters).
 * Returns camelCase param names.
 */
export function extractQueryParams(queryString: string): string[] {
  const paramRegex = /\$(\w+)\s*:/g
  const params: string[] = []
  let match: RegExpExecArray | null
  while ((match = paramRegex.exec(queryString)) !== null) {
    if (match[1] !== "org") params.push(match[1])
  }
  return params
}

/**
 * Extract field names from a TypeScript interface.
 * Returns camelCase field names.
 */
export function extractTsInterfaceFields(filePath: string, interfaceName: string): string[] {
  const source = readFileSync(path.join(ROOT, filePath), "utf-8")
  const ifaceRegex = new RegExp(
    `export\\s+interface\\s+${interfaceName}\\s*\\{([^}]+)\\}`,
    "s"
  )
  const match = source.match(ifaceRegex)
  if (!match) throw new Error(`Interface ${interfaceName} not found in ${filePath}`)

  return match[1]
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("//"))
    .map((line) => line.split(":")[0].replace("?", "").trim())
    .filter((f) => f.length > 0)
}
