# ADR 000 — Phase 1 decisions

Status: Accepted (20 Oct 2026)

## Context

Before building, a few open product and design questions needed a decision.

## Decisions

| Q   | Decision                                                                                                     |
| --- | ------------------------------------------------------------------------------------------------------------ |
| Q4  | Third upstream = GitLab MCP with a dedicated fine-grained PAT (MCP tool: Execute); fallback DeepWiki no-auth |
| Q5  | Dashboard login = email + password (scrypt), admin-created members, admin seeded from a Secret               |
| Q6  | External MCP endpoint = `POST /mcp`, stateless Streamable HTTP, Bearer key checked per request               |
| Q7  | Chat model = Claude Sonnet (latest)                                                                          |

## Consequences

Q5 and Q6 are fixed in the contracts (ADR 001). Q4 and Q7 need `GITLAB_MCP_TOKEN` and
`ANTHROPIC_API_KEY` in `.env.local`.
