import { spawn, type ChildProcess } from "node:child_process"

const IDP_IMAGE = "kristophjunge/test-saml-idp:1.15"
const IDP_PORT = 8484

export interface TestIdp {
  ssoUrl: string
  metadataUrl: string
  username: string
  password: string
  stop: () => Promise<void>
}

/**
 * Returns null if Docker is unavailable — callers should test.skip() in that case.
 * The IdP is configured to redirect SAML assertions back to localhost:3000.
 */
export async function startTestIdp(): Promise<TestIdp | null> {
  if (!(await dockerAvailable())) return null

  const aegisOrigin = "http://localhost:3000"
  const container = spawn("docker", [
    "run", "--rm", "-d",
    "-p", `${IDP_PORT}:8080`,
    "-e", `SIMPLESAMLPHP_SP_ENTITY_ID=${aegisOrigin}/auth/sso/saml/metadata`,
    "-e", `SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE=${aegisOrigin}/auth/sso/saml/acs`,
    IDP_IMAGE,
  ]) as ChildProcess

  const containerId = await new Promise<string>((resolve, reject) => {
    let out = ""
    let err = ""
    container.stdout?.on("data", (c) => (out += c.toString()))
    container.stderr?.on("data", (c) => (err += c.toString()))
    container.on("exit", (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`docker exited ${code}: ${err || out}`))))
  })

  const metadataUrl = `http://localhost:${IDP_PORT}/simplesaml/saml2/idp/metadata.php`
  await waitForUrl(metadataUrl)

  return {
    ssoUrl: `http://localhost:${IDP_PORT}/simplesaml/saml2/idp/SSOService.php`,
    metadataUrl,
    username: "user1",
    password: "user1pass",
    async stop() {
      await new Promise<void>((resolve) => {
        const p = spawn("docker", ["stop", containerId])
        p.on("exit", () => resolve())
      })
    },
  }
}

async function dockerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn("docker", ["info"], { stdio: "ignore" })
    p.on("exit", (code) => resolve(code === 0))
    p.on("error", () => resolve(false))
  })
}

async function waitForUrl(url: string, timeoutMs = 30_000): Promise<void> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url)
      if (r.ok) return
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`Timed out waiting for ${url}`)
}
