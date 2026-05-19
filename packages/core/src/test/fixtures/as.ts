import { createServer } from "node:http"
import type { AddressInfo } from "node:net"
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose"

export interface TestASOptions {
  /** Key algorithm. Defaults to "ES256". */
  alg?: "RS256" | "ES256"
}

export interface TestTokenClaims {
  sub?: string
  aud?: string | string[]
  exp?: number
  nbf?: number
  iss?: string
  scope?: string
  [key: string]: unknown
}

export interface TestAS {
  /** e.g. "http://127.0.0.1:<port>" */
  issuer: string
  /** e.g. "http://127.0.0.1:<port>/.well-known/jwks.json" */
  jwksUri: string
  /**
   * Signs a JWT with the fixture's private key.
   * Defaults: iss=issuer, iat=now, exp=now+3600.
   * Caller may override any claim including iss/aud/exp to craft malformed tokens.
   */
  signToken(claims: TestTokenClaims): Promise<string>
  /** Stops the HTTP server and releases the port. */
  close(): Promise<void>
}

export async function startTestAS(opts?: TestASOptions): Promise<TestAS> {
  const alg = opts?.alg ?? "ES256"
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true })
  const publicJwk = await exportJWK(publicKey)
  publicJwk.kid = "test-key-1"
  publicJwk.alg = alg

  const jwksPayload = JSON.stringify({ keys: [publicJwk] })

  const server = createServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(jwksPayload)
      return
    }
    res.writeHead(404)
    res.end()
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve)
  })

  const { port } = server.address() as AddressInfo
  const issuer = `http://127.0.0.1:${port}`
  const jwksUri = `${issuer}/.well-known/jwks.json`

  async function signToken(claims: TestTokenClaims): Promise<string> {
    const now = Math.floor(Date.now() / 1000)

    const { sub, aud, exp, nbf, iss, ...extraClaims } = claims

    let builder = new SignJWT(extraClaims)
      .setProtectedHeader({ alg, kid: "test-key-1" })
      .setIssuedAt()
      .setIssuer(iss ?? issuer)
      .setExpirationTime(exp ?? now + 3600)

    if (sub !== undefined) builder = builder.setSubject(sub)
    if (aud !== undefined) builder = builder.setAudience(aud)
    if (nbf !== undefined) builder = builder.setNotBefore(nbf)

    return builder.sign(privateKey)
  }

  async function close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  return { issuer, jwksUri, signToken, close }
}

// Re-export jwtVerify for convenience in tests that want to verify tokens
export { jwtVerify }
