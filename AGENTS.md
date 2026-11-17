<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

## Project rules

### Zero State

Do not install Prisma, Drizzle, Supabase, NextAuth, or any database or auth library. Every request runs statelessly. Do not persist scans, sessions, or users.

### SSRF Prevention

Strip protocols, credentials, ports, and paths so only the root hostname remains. Reject IP literals, including obfuscated forms that parse as an address. Resolve DNS with `node:dns/promises` before connecting. Refuse the scan when the name is `localhost` or any resolved address is `127.0.0.1`, `::1`, or inside the private RFC 1918 ranges `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. Also refuse other non-global answers: the rest of `127.0.0.0/8`, `0.0.0.0/8`, link-local `169.254.0.0/16`, CGNAT `100.64.0.0/10`, multicast and reserved space, and IPv6 loopback, unique-local (`fc00::/7`), and link-local (`fe80::/10`). Re-check DNS on every request, including redirects, and do not connect when any answer is non-global.

### Deterministic Core

Use only native Node.js. DNS lookups go through `node:dns/promises`. HTTP checks use `fetch` with `AbortSignal.timeout(8000)`. Do not add third-party or paid scanning APIs.
