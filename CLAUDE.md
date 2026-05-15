# Agent Passport

> Verifiable, identity-rooted delegation tokens for AI agents — built on existing standards (OIDC, OAuth 2.0 Token Exchange, JWT, NIST SP 800-63 Vectors of Trust).

This file is project context for Claude Code. Read it first; it captures decisions already made so you don't re-litigate them and so the implementation stays aligned with NIST's AI Agent Standards Initiative.

---

## Mission

When a user tells an AI agent "do X on my behalf," there is currently no standard, verifiable way for downstream tools, MCP servers, or other agents to know:

1. **Who** the principal is (and how strongly that identity was proofed),
2. **What** authority the agent was actually granted,
3. **For how long** the grant is valid,
4. **What chain** of delegation got us here (user → agent A → agent B → tool C).

Most agent frameworks paper over this with bare API keys. Agent Passport closes the gap by issuing short-lived, scope-bound, NIST-identity-rooted delegation tokens that downstream verifiers can check cryptographically.

This project is a deliberate, concrete contribution to the **Agent Identity & Authorization** pillar of the [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) and the related [NCCOE Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) project.

---

## Audience and primary deliverable

- **Audience:** developers building AI agent frameworks (LangChain, LlamaIndex, AutoGen, MCP runtimes) who need a drop-in identity/authorization primitive.
- **Primary deliverable:** an open-source Python library (`agent-passport`) plus a CLI demo and a small set of `examples/`.
- **Explicitly not in scope (for v0):** a hosted dashboard, a TypeScript SDK, key rotation infrastructure, a production-grade key store. These are deferred until the primitives are right.

---

## Standards baseline

Build on these. Do not invent new crypto, new claim names that duplicate existing ones, or a new identity assurance vocabulary.

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — token format.
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) — signing.
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) — the model for exchanging an OIDC ID token for a delegation token. The `act` claim ([§4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1)) is the standard way to express "agent acting on behalf of user."
- [RFC 8485 — Vectors of Trust](https://datatracker.ietf.org/doc/html/rfc8485) — `vot`/`vtm`/`vtr` for expressing identity assurance in OIDC. Use these where ID.me supports them; otherwise carry their `acr` value forward.
- [NIST SP 800-63-3 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) — defines IAL (Identity Assurance Level), AAL (Authenticator Assurance Level), FAL (Federation Assurance Level). The whole point of this project is to propagate these levels into the agent's delegation token.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the user-authentication step.

If a need arises that an existing RFC covers, use the RFC. New claim names are a last resort and must be namespaced (e.g., `https://agent-passport.org/claims/agent_id`).

---

## Architecture

Three components, in one package:

```
                                        ┌──────────────────────┐
                  OIDC ID token         │                      │
   ┌──────────┐  (with acr=ial2)        │   Token Issuer       │
   │  ID.me   ├────────────────────────▶│   (RFC 8693 token    │
   └──────────┘                         │    exchange)         │
                                        │                      │
                                        └──────────┬───────────┘
                                                   │
                                                   │ short-lived
                                                   │ delegation JWT
                                                   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │   Agent runtime (LangChain / MCP client / custom)           │
   │                                                             │
   │   Carries the delegation JWT on every outbound tool call.   │
   │   When sub-delegating to another agent, mints a child       │
   │   token via the issuer with parent_jti set.                 │
   └─────────────────────────────────────────────────────────────┘
                                                   │
                                                   │
                                                   ▼
                                        ┌──────────────────────┐
                                        │   Token Verifier     │
                                        │                      │
                                        │   Used by MCP        │
                                        │   servers, tool      │
                                        │   APIs, sub-agents.  │
                                        │                      │
                                        │   Checks signature,  │
                                        │   expiry, scope,     │
                                        │   chain, IAL policy. │
                                        └──────────────────────┘
```

**Issuer**: takes a CSP-issued OIDC ID token, validates it, mints a short-lived delegation JWT layering the agent-acting claims on top. Also handles child-token minting for sub-delegation.

**Verifier**: a library and a CLI that any downstream service can use to validate a delegation token. Returns either a structured `VerifiedPassport` object (principal, agent, scope, chain, IAL/AAL) or a typed error.

**OIDC client adapter**: knows how to talk to ID.me (and to a hermetic mock provider for tests). Maps ID.me's `acr` values into the canonical IAL/AAL representation Agent Passport uses internally.

---

## Token claim model

A delegation JWT carries:

**Standard JWT claims (RFC 7519):**
- `iss` — the Agent Passport issuer URL.
- `sub` — pairwise subject identifier from the upstream CSP. Never the user's email or government ID.
- `aud` — the verifier audience (e.g., the MCP server's identifier).
- `iat`, `exp`, `nbf` — short lifetime; default 15 minutes for top-level, 5 minutes for sub-delegated.
- `jti` — unique token ID; used for revocation and as `parent_jti` in children.

**Identity assurance (RFC 8485 + NIST SP 800-63-3):**
- `acr` — pass through the upstream CSP's `acr` value verbatim (e.g., `http://idmanagement.gov/ns/assurance/loa/2` or whatever ID.me returns for IAL2).
- `ial`, `aal`, `fal` — canonical numeric levels (1, 2, or 3) that the verifier can compare against policy. Derived from `acr`.

**Delegation (RFC 8693 §4.1):**
- `act` — an object describing the agent acting on the principal's behalf. Per RFC 8693, may itself contain a nested `act` for chains.

**Agent-specific (namespaced):**
- `https://agent-passport.org/claims/agent_id` — stable identifier for the agent instance.
- `https://agent-passport.org/claims/agent_model` — e.g., `claude-opus-4-7`, `gpt-5`.
- `https://agent-passport.org/claims/tool_scope` — explicit allowlist of tool/endpoint patterns. Strings, glob-style. **Empty array = no authority.**
- `https://agent-passport.org/claims/task_purpose` — short human-readable string explaining intent ("book a flight from SFO to JFK on Tuesday"). Used in audit logs, surfaced to verifiers for policy.
- `https://agent-passport.org/claims/parent_jti` — `jti` of the parent token in a delegation chain. Absent on root tokens.

**Scope attenuation rule**: a child token's `tool_scope` MUST be a subset of its parent's. The issuer enforces this when minting children. The verifier re-checks at validation time when walking chains.

---

## ID.me integration

ID.me sandbox credentials are being provisioned by the project sponsor. **Do not paste them into chat or commit them.** They live in a `.env` file at the project root, loaded at runtime via `python-dotenv` or equivalent. `.env` is in `.gitignore`. Provide a `.env.example` with placeholder values.

**Required env vars:**
```
IDME_CLIENT_ID=...
IDME_CLIENT_SECRET=...
IDME_REDIRECT_URI=http://localhost:8765/callback
IDME_DISCOVERY_URL=https://api.id.me/.well-known/openid-configuration  # verify exact URL from docs
IDME_SCOPES=openid,...                                                  # verify exact scope names from docs
```

**Documentation to read before writing the adapter:**
- [docs.id.me — OIDC / OpenID Connect configuration](https://docs.id.me/guides/open-id-connect/configuration)
- [docs.id.me — OAuth 2.0 overview](https://docs.id.me/guides/o-auth-2-0/overview)
- [developers.id.me — Federated Protocols / OIDC](https://developers.id.me/documentation/federated-protocols/oidc)
- [developers.id.me — Identity Verification OIDC](https://developers.id.me/documentation/identity/oidc/overview)
- [developers.id.me — MFA OIDC overview](https://developers.id.me/documentation/mfa/oidc/overview)
- [docs.id.me — OIDC Ruby sample code](https://docs.id.me/integrations/sample-code/options/oidc-ruby) — useful as a reference implementation.

**Known ID.me-specific facts (from their docs):**
- Built on OAuth 2 (draft-22).
- `access_token` lifetime is 5 minutes — design refresh strategy accordingly. Note: Agent Passport delegation tokens are independent of this; the ID.me access token is only used to fetch the ID token / userinfo at the start of a session.
- Both full-page redirect and popup auth flows are supported.
- Exact `acr` URI strings, scope names, and userinfo claim shapes vary by ID.me product line — read the discovery doc and the configuration page for ground truth before hardcoding anything.

**Mapping ID.me `acr` → canonical IAL/AAL/FAL:** implement this in a single `idme_adapter.py` function so the mapping is auditable and changes when ID.me updates its `acr` URIs don't ripple through the codebase.

---

## Mock OIDC provider

A small in-process OIDC provider that issues realistic ID tokens with proper VoT/`acr` claims. Its only job is to make the test suite hermetic so contributors don't need ID.me sandbox credentials to run tests. It is **not** a security boundary, **not** a quickstart for end users (the README's quickstart should target real ID.me), and **not** shipped as a public-facing component.

Lives in `tests/fixtures/mock_oidc/`. Uses an ephemeral RSA keypair generated at test-suite startup. Publishes a JWKS endpoint on a random localhost port so the issuer can validate tokens against it normally.

---

## CLI surface

```
agent-passport login                 # runs the OIDC dance against ID.me, stores ID token locally
agent-passport issue                 # mints a delegation token from the stored ID token
    --agent-id <id>
    --agent-model <model>
    --tool-scope <pattern>           # repeatable
    --task-purpose <string>
    --aud <audience>
    --ttl <seconds>                  # default 900
agent-passport verify <token>        # validates signature/expiry/scope; prints VerifiedPassport
    --require-ial <n>
    --require-aal <n>
    --aud <audience>
    --required-scope <pattern>
agent-passport inspect <token>       # decodes and pretty-prints all claims, including the chain
agent-passport delegate <token>      # mints a child token; --tool-scope must be a subset
    --agent-id <id>
    --tool-scope <pattern>
    --ttl <seconds>                  # default 300
```

The CLI is the primary demo surface. README quickstart should walk through `login` → `issue` → `inspect` → `verify` end-to-end.

---

## Examples

`examples/` ships with:

1. **`mcp_middleware.py`** — wraps an MCP server so it requires an Agent Passport on connect. Each tool registers a required scope; the middleware rejects calls whose token doesn't cover the scope.
2. **`langchain_tool_wrapper.py`** — a `Tool` subclass (or equivalent for the current LangChain API) that validates the passport before calling the wrapped tool.
3. **`multi_agent_chain.py`** — end-to-end demo: user authenticates via mock provider, mints a token with broad scope, delegates a narrower token to agent A, which delegates a still-narrower token to agent B, which calls a tool. Verifier walks the chain and prints the full delegation tree.

Examples should be runnable standalone, with comments that explain the standards being applied.

---

## Project layout

```
agent-passport/
├── pyproject.toml
├── README.md                  # public-facing: rationale, quickstart, NIST refs
├── CLAUDE.md                  # this file
├── .env.example
├── .gitignore                 # excludes .env, *.pem, dist/, etc.
├── src/
│   └── agent_passport/
│       ├── __init__.py
│       ├── claims.py          # Pydantic models for the token claim schema
│       ├── issuer.py          # token-exchange logic
│       ├── verifier.py        # signature, scope, chain, IAL policy
│       ├── policy.py          # IAL/AAL policy types
│       ├── keys.py            # JWK loading, JWKS publishing
│       ├── oidc/
│       │   ├── __init__.py
│       │   ├── base.py        # generic OIDC client interface
│       │   └── idme_adapter.py
│       └── cli.py             # Click- or Typer-based CLI
├── examples/
│   ├── mcp_middleware.py
│   ├── langchain_tool_wrapper.py
│   └── multi_agent_chain.py
└── tests/
    ├── fixtures/
    │   └── mock_oidc/         # in-process mock CSP
    ├── test_claims.py
    ├── test_issuer.py
    ├── test_verifier.py
    ├── test_chain_attenuation.py
    └── test_idme_adapter.py
```

---

## Build commands

```bash
# install (editable, with dev extras)
pip install -e '.[dev]'

# run tests
pytest

# run tests with coverage
pytest --cov=agent_passport --cov-report=term-missing

# lint and format
ruff check .
ruff format .

# type check
mypy src/

# run the CLI from source
python -m agent_passport --help
```

Use Python 3.11+. Use Pydantic v2. Use `authlib` or `pyjwt` for JWT handling — do not implement JOSE primitives by hand. Use `httpx` for HTTP. Use `Typer` for the CLI (better ergonomics than Click for typed commands).

---

## Coding conventions

- **Type-annotate everything.** `mypy --strict` should pass on `src/`.
- **Pydantic models for all claim shapes.** Validation at the boundary, dataclasses inside.
- **Errors are typed.** Custom exception hierarchy rooted at `AgentPassportError`. Verification failures distinguish `InvalidSignature`, `Expired`, `ScopeViolation`, `IALInsufficient`, `ChainBroken`, etc. — verifier callers should be able to make policy decisions on the error type.
- **No global state.** Issuer and verifier are classes you instantiate with config (key material, allowed audiences, policy).
- **Tests first for the verifier.** It's the security-critical component; every error path should have a test.
- **Time is injected.** Pass a `now: Callable[[], datetime]` into the verifier so tests can pin time without monkey-patching.
- **Logs are structured.** Use `structlog` or stdlib `logging` with extras; never log token contents at INFO level (only `jti`).

---

## Security guardrails

- **Never log a full token at INFO or above.** Log `jti`, `sub`, `agent_id`, `iss`, `aud`. The full token is a bearer credential.
- **Never accept `alg: none`.** Reject any JWS with no signature. Pin allowed algorithms to `RS256`, `ES256`, `EdDSA`.
- **Verify `iss` and `aud` strictly.** Allowlist of issuers, exact-match on audience.
- **Enforce `exp` and `nbf` with a small clock-skew tolerance** (≤30 seconds).
- **Scope attenuation is enforced at issuance AND at verification.** Defense in depth.
- **The CSP's `acr` is the source of truth for IAL.** Do not let a downstream agent claim a higher IAL than the root token — verifier checks that the chain's IAL is monotonically non-increasing.
- **Reject tokens whose `tool_scope` claims `*` unless the verifier's policy explicitly opts in.** The default-deny stance is part of the value prop.

---

## Suggested first task sequence for Claude Code

Work in this order; each step has a natural test gate:

1. **Scaffold the package** — `pyproject.toml`, `src/`, `tests/`, `.env.example`, `.gitignore`, basic README skeleton. Confirm `pip install -e '.[dev]'` and `pytest` (with no tests) pass.
2. **Write the claim model** — `claims.py` with Pydantic models for `Passport`, `ActClaim`, `AgentClaims`. Round-trip tests (Passport → JWT → Passport).
3. **Implement the verifier first, before the issuer** — write the verifier against hand-crafted test JWTs. This nails down the security contract before there's any temptation to make the issuer "just work" with the verifier's bugs.
4. **Stand up the mock OIDC provider** — pytest fixture that boots an in-process provider on a random port with an ephemeral RSA keypair.
5. **Implement the issuer** — RFC 8693 token exchange against the mock provider. Test the whole loop: ID token in → delegation token out → verifier accepts.
6. **Implement chain delegation** — child-token minting, scope attenuation enforcement, chain walking on verify.
7. **Build the CLI** — Typer-based, thin wrappers over the library.
8. **ID.me adapter** — implement against the docs (links above), test against the mock provider with ID.me-shaped `acr` values, leave the live-sandbox test gated behind an env var so CI doesn't need creds.
9. **Examples** — write the three example files. Each one should run from a clean checkout.
10. **README** — public-facing quickstart targeting real ID.me; rationale; NIST/RFC references; pointer to CLAUDE.md for design context.
11. **Polish** — ruff, mypy, coverage. Ship.

---

## What to do if something feels wrong

If you hit a design question this doc doesn't answer, default to:
1. **What do the relevant RFCs say?** Read them; don't guess.
2. **What does the NIST SP 800-63-3 vocabulary call this?** Use that name.
3. **What's the most restrictive interpretation?** This is a security library; default-deny.
4. **Would a security reviewer raise an eyebrow?** If yes, restructure.

If a question is genuinely undecidable from those, leave a clearly-marked `# DESIGN NOTE:` comment and surface it in the PR description rather than silently picking.

---

## References

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NCCOE — Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- [NIST SP 800-63-3 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8485 — Vectors of Trust](https://datatracker.ietf.org/doc/html/rfc8485)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [ID.me OIDC docs (overview)](https://docs.id.me/guides/open-id-connect/configuration)
- [ID.me Developers — Federated Protocols / OIDC](https://developers.id.me/documentation/federated-protocols/oidc)
