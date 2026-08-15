# IP Allowlist — `dev.mcpg.ip-allowlist`

> class `tool_gate` · `native` · package `mcpg-plugin-security-ip-allowlist` · artifact `libmcpg_plugin_security_ip_allowlist.so` · Apache-2.0

A pre-dispatch tool gate that admits a call only when the caller's IP address
falls inside one of the CIDR ranges you list, and denies it otherwise. Ranges
are parsed once at load, matching is a plain containment check over IPv4 and
IPv6, and an address that cannot be resolved at all is treated as a denial.
Reach for it when tool access should be confined to known network ranges — an
office range, a VPN pool, a partner's egress block — independent of who the
caller claims to be.

## What it does
- Parses every `allow` entry into a network at load time. An unparseable CIDR
  refuses to register rather than silently shrinking the allowlist.
- Reads the caller's address from a `_request_headers` map on the evaluation
  config, taking the first comma-separated value of `ip_header` and falling back
  to `x-real-ip`.
- Normalises IPv4-mapped IPv6 addresses before matching, so `::ffff:10.0.0.1` is
  covered by an allowlist entry of `10.0.0.0/8` and a dual-stack hop cannot slip
  past an IPv4 range.
- Denies with HTTP `403` and JSON-RPC code `-32030`, both when the address is
  outside every range and when no address can be resolved.
- Applies to every tool by default; `tools` narrows it to matching names using
  glob patterns, where `*` matches any sequence and `?` exactly one character.
- Allows unconditionally post-dispatch — this is an admission control and has
  nothing to say about results.
- Runs entirely in-process. It declares no capabilities and opens no sockets.

## Configuration
Loaded from the flat top-level `plugins:` list. Every `tool_gate` entry joins
one chain evaluated in list order, and the first deny short-circuits the call.

```yaml
plugins:
  - id: dev.mcpg.ip-allowlist
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_security_ip_allowlist.so }
    config:
      allow:
        - "10.0.0.0/8"
        - "192.168.1.0/24"
        - "::1/128"
      ip_header: x-forwarded-for
      tools: []          # empty = gate every tool
```

To pull the published artifact instead of building it, write
`source: { oci: ghcr.io/mcpg-dev/source-code/plugins/ip-allowlist:protocol-1 }`.
The reference is platform-agnostic; the gateway resolves the variant for its own
OS, architecture and libc.

| Field | Type | Default | Description |
|---|---|---|---|
| `allow` | array of CIDR | — (required) | Networks admitted, IPv4 or IPv6. An invalid entry refuses the load. |
| `ip_header` | string | `x-forwarded-for` | Header name read from the evaluation config's `_request_headers` map. |
| `tools` | array of glob | `[]` | Tool names this gate applies to; empty means every tool. |

Unknown fields are rejected.

## Security
- **Know where the address comes from.** The gate does not open a socket and has
  no view of the transport peer: it reads the address out of a `_request_headers`
  map inside the config object it is handed at evaluation time. A host that does
  not populate that map leaves the gate with nothing to match, and every gated
  call is denied. Confirm the address actually arrives before relying on this
  gate as your only network control.
- **The leftmost forwarded hop is used.** `X-Forwarded-For` is read from its
  first value, and there is no trusted-proxy-depth accounting, so a caller able
  to set the header chooses the address the gate sees. Deploy behind a proxy that
  overwrites the header rather than appending to it.
- **Bad configuration fails the load.** An invalid CIDR aborts construction,
  which the host turns into a registration failure. The gate never runs with a
  partially parsed allowlist.
- **Addresses stay out of metric labels.** The resolved address appears in audit
  details and in the deny message, never as a metric or span label, so a hostile
  caller cannot inflate series cardinality by rotating source addresses.

## Observability
Every pre-dispatch evaluation records `mcpg_ip_allowlist_evaluate_ms`. Each
evaluation that actually reaches a decision — the tool is in scope — increments
`mcpg_ip_allowlist_decisions_total`, labelled with `decision` (`allow` / `deny`)
and `reason` (`in_allowlist`, `not_in_allowlist`, `no_ip`).

When the host installs its observability handle, the gate additionally opens an
`ip_allowlist.check` span and reports `mcpg_ip_allowlist_decision_seconds` plus
`mcpg_ip_allowlist_decisions_total` labelled by `outcome`. Denials emit a
`dev.mcpg.ip_allowlist.rejected` audit event carrying the tool, the reason, the
configured header, the caller's subject and — when one was resolved — the client
address.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; a binary that links several plugins together turns
it off so they do not all export `mcpg_plugin_register`:

```bash
cargo build -p mcpg-plugin-security-ip-allowlist --features cdylib-export --release   # → target/release/libmcpg_plugin_security_ip_allowlist.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, the ABI, and how entries load:
  <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema, including `plugins[]`:
  <https://mcpg.dev/docs/reference/configuration>
- Restrict calls by wall-clock window instead of by network:
  `libs/plugins/security/tool-gate-business-hours`
- Express richer admission rules as policy:
  `libs/plugins/security/policy-casbin`
