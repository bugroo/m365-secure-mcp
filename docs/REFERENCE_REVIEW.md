# Review of related Microsoft 365 MCP projects

Reviewed on 2026-07-26 from their public GitHub repositories.

## aixolotl/microsoft-planner-mcp

Useful patterns adopted:

- Planner tools grouped by domain.
- ETag/`If-Match` handling for updates.
- Separate `plannerTaskDetails` reads and writes using the details-specific
  ETag. This project narrows the write contract to description, preview, and
  additive/existing checklist changes.
- Clean MCP errors, rate limiting, structured audit/telemetry concepts.
- Explicit per-client consent for a remote MCP OAuth proxy.

Not adopted:

- Remote HTTP + custom `api://<client-id>` resource + OBO is unnecessary for
  the local stdio goal and creates a second OAuth trust boundary.
- Planner delete tools are outside this project's risk posture.
- `Tasks.ReadWrite` is not requested for the read profile.

Source: <https://github.com/aixolotl/microsoft-planner-mcp>

## Softeria/ms-365-mcp-server

Useful patterns adopted:

- Tool-to-permission mapping and a permissions diagnostic.
- Module/preset-based surface reduction. This project extends it with exact
  tool allowlists/denylists and resource-level gates.
- Read-only operating mode.
- Audit logging, bounded tool discovery, and stable Graph service categories.

Not adopted:

- A flat surface of hundreds of simultaneously visible endpoint wrappers. This
  project keeps broad domain coverage but exposes only the selected subset.
- The repository currently uses npm/package-lock. This project does not import
  it as a runtime dependency.
- Generic organization mode can imply broad permissions; our modules and
  resources remain explicitly allowlisted.

Source: <https://github.com/Softeria/ms-365-mcp-server>

## merill/lokka

Useful patterns adopted:

- Support for interactive delegated authentication with a custom Entra app.
- Certificate preference over client secrets for future daemon scenarios.
- Explicit ability to pin Graph to `v1.0`.

Explicitly rejected:

- A tool accepting an arbitrary API path, HTTP method, query, and body.
- `DELETE` capability in a generic Graph proxy.
- Graph `beta` as the default.
- Passing a Graph access token through an MCP tool.
- Runtime permission expansion through a model-callable tool.
- App-only tenant access in the interactive local profile.

Those capabilities are powerful for an administrator-controlled laboratory but
do not meet this project's least-privilege and prompt-injection boundaries.

Source: <https://github.com/merill/lokka>

## MCPMarket personalized installer

The supplied installer was downloaded for static review only and was not
executed. SHA-256 at review time:
`4c3ed5bfb1dc13a5df37377b0a76cc435fc811fdb53166458983d10c5d801b97`.

Useful pattern adopted:

- Operator-controlled toolkits make a broad capability catalog practical while
  keeping each client/session narrowly scoped.

Security findings that prevent adoption of the installer:

- It embeds a personalized bearer credential in generated configuration files
  instead of relying only on an environment reference or OS keychain.
- It installs persistent session/post-tool hooks and enables global Codex hook
  feature flags.
- It mutates the user's global Codex configuration and marketplace registry.
- It contains outbound synchronization and telemetry calls.
- The `curl | bash` flow has no signature or human review checkpoint.

This MCP therefore uses local stdio, OS-keychain MSAL tokens, explicit client
templates, no lifecycle hooks, and no external telemetry.
