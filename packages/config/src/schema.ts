/**
 * Runtime schema validation for `AuthKitConfig` shapes loaded from a config
 * file. The TS public API is checked by the compiler at the
 * `createAuthKit(config)` call site; this schema covers the case where the
 * config crosses a runtime boundary (config file → loader).
 *
 * Function-typed and class-instance fields (`tokenStore`, `resolveUserScopes`,
 * `customMatchers`, `audit.onEvent`) are validated structurally: we check
 * that they are callable / object-shaped, not that their full contract
 * holds. The TypeScript types catch the rest.
 *
 * Spec: docs/spec/v0.2.md#58-config-file-format
 *       docs/spec/v0.2.md#12-security-non-negotiables-additions  (bounded load)
 */
import { z } from "zod"

// biome-ignore lint/suspicious/noExplicitAny: zod `custom` predicate handle
const isFunction = (v: unknown): v is (...args: any[]) => unknown => typeof v === "function"

// biome-ignore lint/suspicious/noExplicitAny: zod custom output is a function type
const fn = () => z.custom<(...args: any[]) => unknown>(isFunction, { error: "Expected a function" })

const scopeVocabularyEntrySchema = z.object({
  description: z.string(),
  resource: z.string().optional(),
  implies: z.array(z.string()).readonly().optional(),
})

const authorizationServerSchema = z.object({
  issuer: z.string().min(1),
  jwksUri: z.string().min(1),
  introspectionEndpoint: z.string().optional(),
  jwksCacheTtlMs: z.number().int().nonnegative().optional(),
})

const patSchema = z.object({
  enabled: z.boolean(),
  prefix: z.string().optional(),
  defaultExpiryDays: z.number().int().positive().optional(),
  maxExpiryDays: z.number().int().positive().optional(),
  rotationGraceSeconds: z.number().int().nonnegative().optional(),
})

const bypassSchema = z.object({
  enabled: z.boolean(),
  user: z.string().min(1),
  scopes: z.array(z.string()).readonly(),
  allowInProduction: z.boolean().optional(),
})

const staticTokenSchema = z.object({
  token: z.string().min(1),
  user: z.string().min(1),
  scopes: z.array(z.string()).readonly(),
})

/**
 * `TokenStore` is an interface with ten required methods and two optional
 * ones. We accept any object whose required slots are functions; class
 * instances pass because methods are own/inherited properties of the
 * resulting object.
 */
const tokenStoreSchema = z.looseObject({
  createPat: fn(),
  findPatByHash: fn(),
  listPatsByUser: fn(),
  revokePat: fn(),
  rotatePat: fn(),
  updatePatLastUsed: fn(),
  createRefreshToken: fn(),
  findRefreshToken: fn(),
  rotateRefreshToken: fn(),
  revokeRefreshTokenFamily: fn(),
  init: fn().optional(),
  close: fn().optional(),
})

export const authKitConfigSchema = z.object({
  resourceIndicator: z.string().min(1),
  auth: z.object({
    authorizationServer: authorizationServerSchema.optional(),
    tokenStore: tokenStoreSchema,
    pat: patSchema,
    bypass: bypassSchema.optional(),
    staticToken: staticTokenSchema.optional(),
  }),
  scopes: z.object({
    vocabulary: z.record(z.string(), scopeVocabularyEntrySchema),
    customMatchers: z.array(fn()).readonly().optional(),
  }),
  resolveUserScopes: fn(),
  logger: z.unknown().optional(),
  audit: z
    .object({
      onEvent: fn().optional(),
    })
    .optional(),
  http: z
    .object({
      allowedHosts: z.array(z.string()).readonly().optional(),
    })
    .optional(),
})
