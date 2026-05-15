# Agent Passport

> Verifiable, identity-rooted delegation tokens for AI agents — built on existing standards (OIDC, OAuth 2.0 Token Exchange, JWT, NIST SP 800-63 Vectors of Trust).

**Status:** pre-alpha. Spec is in [`CLAUDE.md`](./CLAUDE.md). Code is being scaffolded.

When a user tells an AI agent "do X on my behalf," there is currently no standard, verifiable way for downstream tools, MCP servers, or other agents to know:

1. **Who** the principal is (and how strongly that identity was proofed),
2. **What** authority the agent was actually granted,
3. **For how long** the grant is valid,
4. **What chain** of delegation got us here (user → agent A → agent B → tool C).

Agent Passport closes the gap by issuing short-lived, scope-bound, NIST-identity-rooted delegation tokens that downstream verifiers can check cryptographically.

## Standards baseline

- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8485 — Vectors of Trust](https://datatracker.ietf.org/doc/html/rfc8485)
- [NIST SP 800-63-3 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

## Quickstart

(placeholder — populated once the verifier and mock OIDC provider land)

## Development

```bash
uv venv --python 3.13
uv pip install -e '.[dev]'
uv run pytest
uv run ruff check .
uv run mypy src/
```

## License

TBD.
