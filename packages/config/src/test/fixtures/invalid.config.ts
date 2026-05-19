// Intentionally missing required `auth.pat`, `scopes`, `resolveUserScopes`.
// Used to exercise loadConfig's schema-validation error path.
export default {
  resourceIndicator: "",
  auth: {
    tokenStore: { notAFunction: 1 },
  },
}
