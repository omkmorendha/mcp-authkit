export { defineConfig } from "./define.js"
export { ConfigLoadError, type LoadConfigOptions, loadConfig } from "./load.js"
export { redactConfigForLog } from "./redact.js"
export { authKitConfigSchema } from "./schema.js"
export type {
  AuditEvent,
  AuthContextLike,
  AuthKitConfig,
  LoggerLike,
  ScopeMatcher,
  ScopeVocabulary,
  ScopeVocabularyEntry,
} from "./types.js"
