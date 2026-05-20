import { defineConfig } from "vitepress"

// Site for the mcp-authkit framework. Sources are the existing markdown
// in docs/ — no content moves, the site reads them in place. Sidebar and
// nav mirror the structure of docs/ so a contributor browsing files on
// GitHub sees the same hierarchy as a visitor browsing the site.

export default defineConfig({
  title: "mcp-authkit",
  description:
    "OAuth + PAT auth for Model Context Protocol servers. Validate spec-compliant tokens, mint Personal Access Tokens, and enforce per-tool scopes without wiring auth into every handler.",
  lang: "en-US",
  cleanUrls: true,

  // The repo lives at https://omkmorendha.github.io/mcp-authkit/ on GitHub
  // Pages, so the site assets and links need the /mcp-authkit/ prefix.
  base: "/mcp-authkit/",

  lastUpdated: true,

  // ../examples and ../CHANGELOG live outside docs/ on purpose — they're
  // top-level repo artifacts that this site documents but doesn't render.
  // The relative links work for someone reading the markdown on GitHub;
  // VitePress just can't resolve them.
  ignoreDeadLinks: [
    /examples\//,
    /CHANGELOG/,
  ],

  head: [
    ["link", { rel: "icon", href: "/mcp-authkit/favicon.svg", type: "image/svg+xml" }],
    ["meta", { name: "theme-color", content: "#0ea5e9" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "mcp-authkit" }],
    ["meta", { property: "og:title", content: "mcp-authkit — OAuth + PAT for MCP servers" }],
    ["meta", {
      property: "og:description",
      content: "Validate OAuth 2.1 tokens, mint Personal Access Tokens, and enforce per-tool scopes — without wiring auth into every handler.",
    }],
  ],

  themeConfig: {
    logo: { src: "/logo.svg", width: 24, height: 24 },
    siteTitle: "mcp-authkit",

    nav: [
      { text: "Guide", link: "/quickstart", activeMatch: "^/(quickstart|production)" },
      { text: "Cookbook", link: "/cookbook/", activeMatch: "^/cookbook/" },
      { text: "Spec", link: "/spec/v0.2", activeMatch: "^/spec/" },
      {
        text: `v0.2.1`,
        items: [
          { text: "Changelog", link: "https://github.com/omkmorendha/mcp-authkit/blob/main/CHANGELOG.md" },
          { text: "Releases", link: "https://github.com/omkmorendha/mcp-authkit/releases" },
          { text: "npm: mcp-authkit", link: "https://www.npmjs.com/package/mcp-authkit" },
        ],
      },
    ],

    sidebar: {
      "/": [
        {
          text: "Getting started",
          items: [
            { text: "Quickstart", link: "/quickstart" },
            { text: "Production guide", link: "/production" },
          ],
        },
        {
          text: "Cookbook",
          collapsed: false,
          items: [
            { text: "Overview", link: "/cookbook/" },
            { text: "Hono adapter", link: "/cookbook/hono-adapter" },
            { text: "Postgres store", link: "/cookbook/postgres-store" },
            { text: "SQLite store", link: "/cookbook/sqlite-store" },
            { text: "Redis cache", link: "/cookbook/redis-cache" },
            { text: "Multi-tenant", link: "/cookbook/multi-tenant" },
            { text: "Upstream credentials", link: "/cookbook/upstream-credentials" },
            { text: "Production stdio", link: "/cookbook/production-stdio" },
          ],
        },
        {
          text: "Reference",
          items: [
            { text: "Active spec — v0.2", link: "/spec/v0.2" },
            { text: "Baseline — v0.1", link: "/spec/v0.1" },
            { text: "Dependency graph", link: "/dependency-graph" },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/omkmorendha/mcp-authkit" },
      { icon: "npm", link: "https://www.npmjs.com/package/mcp-authkit" },
    ],

    editLink: {
      pattern: "https://github.com/omkmorendha/mcp-authkit/edit/main/docs/:path",
      text: "Edit this page on GitHub",
    },

    search: { provider: "local" },

    footer: {
      message:
        'Released under the <a href="https://github.com/omkmorendha/mcp-authkit/blob/main/LICENSE">MIT License</a>.',
      copyright: "Copyright © 2026 Om Morendha",
    },

    outline: { level: [2, 3], label: "On this page" },
  },
})
