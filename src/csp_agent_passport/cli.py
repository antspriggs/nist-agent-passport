"""`csp-agent-passport` command-line interface.

Thin Typer wrapper over the library. Five subcommands per CLAUDE.md:

  login     OAuth code+PKCE flow against the configured CSP (RFC 8252).
  issue     Mint a root delegation token from a stored ID token.
  verify    Verify a Passport against a policy; print the verified contents.
  inspect   Decode (no signature check) and pretty-print all claims.
  delegate  Mint a child Passport from a parent (with attenuated scope).

State lives under `$XDG_DATA_HOME/csp-agent-passport/` (see `_storage.py`). CSP
config (discovery URL, client id/secret, redirect URI, scopes) comes from the
environment as a generic `CSP_*` namespace — works with any OIDC + PKCE
provider. Defaults in `.env.example` ship a placeholder discovery URL you
override per deployment.

All commands that accept a token also accept it on stdin (`-` or absent argument).
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from base64 import urlsafe_b64decode
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from dotenv import load_dotenv

from csp_agent_passport import (
    AcrMapping,
    DelegationRequest,
    IDTokenValidator,
    InMemoryKeyStore,
    IssuanceRequest,
    Issuer,
    VerificationPolicy,
    Verifier,
    ial_acr_mapping,
)
from csp_agent_passport._login import LoginError, login_local_loopback
from csp_agent_passport._storage import (
    IDTokenMeta,
    load_id_token,
    load_or_create_issuer_key,
    save_id_token,
    xdg_data_dir,
)

app = typer.Typer(
    name="csp-agent-passport",
    help="Verifiable, identity-rooted delegation tokens for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _env(name: str, default: str | None = None) -> str | None:
    load_dotenv()
    v = os.environ.get(name)
    return v if v is not None else default


def _required_env(name: str) -> str:
    v = _env(name)
    if not v:
        typer.secho(
            f"Required environment variable {name!r} is not set. "
            f"See .env.example for the full list.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    return v


def _issuer_url() -> str:
    return _env("AGENT_PASSPORT_ISSUER") or "https://issuer.local"


def _resolve_acr_mapping() -> AcrMapping:
    """Pick the ACR mapping based on `CSP_ACR_MAPPING` (default 'ial').

    Accepts: 'ial' (the built-in NIST 800-63-3 mapping, which also handles
    the legacy `…/loa/N` URIs some CSPs still emit), or
    'package.module:function_name' to import a custom `AcrMapping` for any
    CSP that emits ACR values outside the built-in set.
    """
    raw = (_env("CSP_ACR_MAPPING") or "ial").strip()
    if raw.lower() == "ial":
        return ial_acr_mapping
    if ":" in raw:
        module_path, func_name = raw.split(":", 1)
        try:
            mod = importlib.import_module(module_path)
            fn = getattr(mod, func_name)
        except (ImportError, AttributeError) as e:
            typer.secho(
                f"Could not load CSP_ACR_MAPPING={raw!r}: {type(e).__name__}: {e}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2) from e
        # Caller's responsibility that fn satisfies AcrMapping; we trust the
        # import-path contract.
        return fn  # type: ignore[no-any-return]
    typer.secho(
        f"Unknown CSP_ACR_MAPPING={raw!r}; expected 'ial' or 'package.module:function_name'.",
        fg=typer.colors.RED,
        err=True,
    )
    raise typer.Exit(code=2)


def _read_token_arg(token_arg: str | None) -> str:
    """Return a token from positional arg or stdin.

    A literal `-` or missing arg means stdin. Whitespace stripped.
    """
    if token_arg is None or token_arg == "-":
        if sys.stdin.isatty():
            typer.secho("No token given and stdin is a TTY.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        data = sys.stdin.read().strip()
        if not data:
            typer.secho("Empty token on stdin.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        return data
    return token_arg.strip()


def _decode_payload(token: str) -> dict[str, Any]:
    """Decode a JWT payload without signature check. For display only."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a compact JWS (expected 3 segments)")
    payload_b64 = parts[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    decoded: Any = json.loads(urlsafe_b64decode(padded))
    if not isinstance(decoded, dict):
        raise ValueError("JWT payload is not a JSON object")
    return decoded


def _make_issuer(now: Any = None) -> Issuer:
    """Construct an Issuer wired to the configured CSP and stored signing key."""
    discovery_url = _required_env("CSP_DISCOVERY_URL")
    client_id = _required_env("CSP_CLIENT_ID")
    validator = IDTokenValidator(
        discovery_url=discovery_url,
        client_id=client_id,
        acr_mapping=_resolve_acr_mapping(),
    )
    return Issuer(
        issuer_url=_issuer_url(),
        signing_key=load_or_create_issuer_key(),
        oidc_client=validator,
    )


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #


@app.command()
def login(
    id_token: Annotated[
        str | None,
        typer.Option(
            "--id-token",
            help="Paste-in mode: skip the OAuth dance and store this token directly.",
        ),
    ] = None,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="Print the auth URL instead of opening a browser."),
    ] = False,
) -> None:
    """Authenticate against the configured CSP and store the resulting ID token."""
    discovery_url = _required_env("CSP_DISCOVERY_URL")
    client_id = _required_env("CSP_CLIENT_ID")

    if id_token is not None:
        path = save_id_token(
            id_token.strip(),
            IDTokenMeta(discovery_url=discovery_url, client_id=client_id),
        )
        typer.secho(f"ID token stored at {path}", fg=typer.colors.GREEN)
        return

    client_secret = _env("CSP_CLIENT_SECRET")
    redirect_uri = _env("CSP_REDIRECT_URI") or "http://localhost:8765/callback"
    scopes_raw = _env("CSP_SCOPES") or "openid"
    scopes = scopes_raw.split()

    try:
        result = login_local_loopback(
            discovery_url=discovery_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
            open_browser=not no_browser,
        )
    except LoginError as e:
        typer.secho(f"login failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    path = save_id_token(
        result.id_token,
        IDTokenMeta(discovery_url=discovery_url, client_id=client_id),
    )
    typer.secho(f"ID token stored at {path}", fg=typer.colors.GREEN)


# --------------------------------------------------------------------------- #
# issue
# --------------------------------------------------------------------------- #


@app.command()
def issue(
    agent_id: Annotated[str, typer.Option("--agent-id", help="Stable identifier for the agent.")],
    agent_model: Annotated[
        str, typer.Option("--agent-model", help="Model name, e.g. claude-opus-4-7.")
    ],
    aud: Annotated[str, typer.Option("--aud", help="Verifier audience (e.g. MCP server URL).")],
    tool_scope: Annotated[
        list[str] | None,
        typer.Option(
            "--tool-scope",
            help="Tool scope pattern (fnmatch). Repeat for multiple. Empty = no authority.",
        ),
    ] = None,
    task_purpose: Annotated[
        str | None,
        typer.Option("--task-purpose", help="Audit-only description of the agent's intent."),
    ] = None,
    ttl: Annotated[
        int,
        typer.Option("--ttl", help="Token lifetime in seconds.", min=1),
    ] = 900,
    id_token: Annotated[
        str | None,
        typer.Option(
            "--id-token", help="Override the stored ID token (defaults to `login` output)."
        ),
    ] = None,
) -> None:
    """Mint a root Agent Passport from the stored ID token."""
    if id_token is None:
        id_token = load_id_token()
        if id_token is None:
            typer.secho(
                "No stored ID token. Run `csp-agent-passport login` first, or pass --id-token.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)

    issuer = _make_issuer()
    token = issuer.issue(
        IssuanceRequest(
            id_token=id_token,
            audience=aud,
            agent_id=agent_id,
            agent_model=agent_model,
            tool_scope=list(tool_scope or []),
            task_purpose=task_purpose,
            ttl=timedelta(seconds=ttl),
        )
    )
    typer.echo(token)


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


@app.command()
def verify(
    token: Annotated[
        str | None,
        typer.Argument(help="Passport JWS, or `-` / omit to read from stdin."),
    ] = None,
    aud: Annotated[str, typer.Option("--aud", help="Expected audience (exact match).")] = "",
    require_ial: Annotated[
        int,
        typer.Option(
            "--require-ial",
            min=0,
            max=3,
            help="Minimum IAL the token must assert (0 = skip check; default).",
        ),
    ] = 0,
    require_aal: Annotated[
        int,
        typer.Option(
            "--require-aal",
            min=0,
            max=3,
            help="Minimum AAL the token must assert (0 = skip check; default).",
        ),
    ] = 0,
    require_fal: Annotated[
        int,
        typer.Option(
            "--require-fal",
            min=0,
            max=3,
            help="Minimum FAL the token must assert (0 = skip check; default).",
        ),
    ] = 0,
    required_scope: Annotated[
        str | None,
        typer.Option("--required-scope", help="Single scope pattern that must be covered."),
    ] = None,
    issuer: Annotated[
        list[str] | None,
        typer.Option(
            "--issuer", help="Trusted issuer URL. Repeat for multiple. Defaults to local issuer."
        ),
    ] = None,
) -> None:
    """Verify a Passport against a policy; print the verified claims on success."""
    if not aud:
        typer.secho("--aud is required.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    tok = _read_token_arg(token)
    trusted = frozenset(issuer) if issuer else frozenset({_issuer_url()})
    key_store = InMemoryKeyStore({})
    # For v0 single-issuer single-user: load the local issuer's public key.
    local_key = load_or_create_issuer_key()
    key_store.add(local_key.thumbprint(), local_key)

    policy = VerificationPolicy(
        issuers=trusted,
        audience=aud,
        require_ial=require_ial,
        require_aal=require_aal,
        require_fal=require_fal,
        required_scope=required_scope,
    )
    v = Verifier(policy, key_store)
    try:
        result = v.verify(tok)
    except Exception as e:
        typer.secho(f"verification failed: {type(e).__name__}: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    p = result.passport
    typer.secho("verified", fg=typer.colors.GREEN)
    typer.echo(
        json.dumps(
            {
                "iss": p.iss,
                "sub": p.sub,
                "aud": p.aud,
                "jti": p.jti,
                "exp": int(p.exp.timestamp()),
                "ial": p.ial,
                "aal": p.aal,
                "fal": p.fal,
                "acr": p.acr,
                "agent_id": p.agent.agent_id,
                "agent_model": p.agent.agent_model,
                "tool_scope": p.agent.tool_scope,
                "task_purpose": p.agent.task_purpose,
                "parent_jti": p.agent.parent_jti,
            },
            indent=2,
        )
    )


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


_NS_PREFIX = "https://agent-passport.org/claims/"


def _walk_act_chain(act: Any) -> list[str]:
    """Walk an RFC 8693 act chain outermost-first, returning each actor's `sub`.

    Outermost `act.sub` is the current actor; nested `act.act.sub` is the actor
    they are acting on behalf of; deepest nested `sub` is the original delegate
    (closest to the principal). Tolerant: a missing `sub` becomes `<missing>`,
    a non-dict nested `act` stops the walk.
    """
    chain: list[str] = []
    cursor: Any = act
    while isinstance(cursor, dict):
        chain.append(str(cursor.get("sub", "<missing>")))
        cursor = cursor.get("act")
    return chain


def _render_tree(payload: dict[str, Any]) -> str:
    """Render a Passport's delegation chain + current-hop metadata as a tree.

    Walks the RFC 8693 `act` chain root-first (deepest first = original delegate;
    outermost = current token holder). For the current hop, surfaces the
    namespaced agent metadata (`agent_model`, `tool_scope`, `task_purpose`)
    plus token-level fields (`jti`, `parent_jti`, `aud`, `iat`, `exp`).

    Tolerant of partial / non-Passport JWTs — missing fields are rendered as
    `<missing>` rather than raising.
    """
    lines: list[str] = []

    principal = payload.get("sub", "<missing>")
    lines.append(f"Principal: {principal}")
    assurance: list[str] = []
    for level in ("ial", "aal", "fal"):
        value = payload.get(level)
        if value is not None:
            assurance.append(f"{level.upper()}={value}")
    if assurance:
        lines.append(f"  [{' '.join(assurance)}]")

    act = payload.get("act")
    if not isinstance(act, dict):
        lines.append("(no `act` claim — not an Agent Passport delegation token)")
        return "\n".join(lines)

    # Outermost-first from _walk_act_chain; reverse for root-first display.
    outer_first = _walk_act_chain(act)
    if not outer_first:
        lines.append("(empty `act` chain)")
        return "\n".join(lines)
    root_first = list(reversed(outer_first))
    last_index = len(root_first) - 1
    for depth, actor_sub in enumerate(root_first):
        indent = "    " * depth
        label_parts: list[str] = []
        if depth == 0 and last_index > 0:
            label_parts.append("(original delegate)")
        if depth == last_index:
            label_parts.append("(current holder)")
        label = "  " + " ".join(label_parts) if label_parts else ""
        lines.append(f"{indent}└── Agent: {actor_sub}{label}")

    # Current-hop metadata under the deepest branch.
    detail_indent = "    " * len(root_first) + "  "
    model = payload.get(_NS_PREFIX + "agent_model")
    if model:
        lines.append(f"{detail_indent}model:        {model}")
    tool_scope = payload.get(_NS_PREFIX + "tool_scope")
    if tool_scope:
        rendered_scope = ", ".join(tool_scope) if isinstance(tool_scope, list) else str(tool_scope)
        lines.append(f"{detail_indent}tool_scope:   {rendered_scope}")
    task_purpose = payload.get(_NS_PREFIX + "task_purpose")
    if task_purpose:
        lines.append(f"{detail_indent}task_purpose: {task_purpose}")
    parent_jti = payload.get(_NS_PREFIX + "parent_jti")
    if parent_jti:
        lines.append(f"{detail_indent}parent_jti:   {parent_jti}")

    # Token-level metadata at the bottom (not part of the tree).
    # Pad label gutter so all values column-align.
    lines.append("")
    footer: list[tuple[str, Any]] = [
        ("Token jti", payload.get("jti", "<missing>")),
        ("Issuer", payload.get("iss", "<missing>")),
        ("Audience", payload.get("aud", "<missing>")),
    ]
    for ts_field, label in (("iat", "Issued at"), ("nbf", "Not before"), ("exp", "Expires")):
        ts = payload.get(ts_field)
        if isinstance(ts, int):
            footer.append((label, datetime.fromtimestamp(ts, tz=UTC).isoformat()))
    label_width = max(len(label) for label, _ in footer) + 1  # +1 for the colon
    for label, value in footer:
        lines.append(f"{label + ':':<{label_width + 2}}{value}")

    return "\n".join(lines)


@app.command()
def inspect(
    token: Annotated[
        str | None,
        typer.Argument(help="Passport JWS, or `-` / omit to read from stdin."),
    ] = None,
    tree: Annotated[
        bool,
        typer.Option(
            "--tree",
            help=(
                "Render the delegation chain as a human-readable tree (root "
                "delegate → current holder) with the current hop's agent "
                "metadata. Default output is full JSON."
            ),
        ),
    ] = False,
) -> None:
    """Decode (no signature check) and pretty-print every claim in the token."""
    tok = _read_token_arg(token)
    try:
        payload = _decode_payload(tok)
    except (ValueError, json.JSONDecodeError) as e:
        typer.secho(f"could not decode token: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    if tree:
        typer.echo(_render_tree(payload))
    else:
        typer.echo(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------- #
# delegate
# --------------------------------------------------------------------------- #


@app.command()
def delegate(
    parent: Annotated[
        str | None,
        typer.Argument(help="Parent Passport JWS, or `-` / omit to read from stdin."),
    ] = None,
    agent_id: Annotated[str, typer.Option("--agent-id")] = "",
    agent_model: Annotated[str, typer.Option("--agent-model")] = "",
    aud: Annotated[
        str,
        typer.Option("--aud", help="Child's audience (may differ from parent's)."),
    ] = "",
    tool_scope: Annotated[
        list[str] | None,
        typer.Option(
            "--tool-scope",
            help="Child tool-scope pattern. Repeat. MUST be a subset of parent's.",
        ),
    ] = None,
    task_purpose: Annotated[str | None, typer.Option("--task-purpose")] = None,
    ttl: Annotated[int, typer.Option("--ttl", min=1)] = 300,
) -> None:
    """Mint a child Passport from a parent (attenuated scope)."""
    for arg_name, val in (("agent_id", agent_id), ("agent_model", agent_model), ("aud", aud)):
        if not val:
            typer.secho(
                f"--{arg_name.replace('_', '-')} is required.", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(code=2)

    parent_tok = _read_token_arg(parent)
    issuer = _make_issuer()
    try:
        verified_parent = issuer.verify_own(parent_tok)
    except Exception as e:
        typer.secho(
            f"could not verify parent token: {type(e).__name__}: {e}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from e

    try:
        child = issuer.delegate(
            DelegationRequest(
                parent=verified_parent,
                audience=aud,
                agent_id=agent_id,
                agent_model=agent_model,
                tool_scope=list(tool_scope or []),
                task_purpose=task_purpose,
                ttl=timedelta(seconds=ttl),
            )
        )
    except Exception as e:
        typer.secho(f"delegation refused: {type(e).__name__}: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    typer.echo(child)


# --------------------------------------------------------------------------- #
# where
# --------------------------------------------------------------------------- #


@app.command()
def where() -> None:
    """Print the XDG data directory used for ID tokens and the issuer key."""
    typer.echo(str(xdg_data_dir()))


if __name__ == "__main__":
    app()
