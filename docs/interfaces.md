# kmesh interfaces

This document describes the current Iroh-based SSH transport. OpenSSH owns SSH host-key verification, SSH user authentication, terminal semantics, SFTP, SCP, and port forwarding. kmesh carries the byte stream and applies access policy before that stream becomes active.

## Client configuration and server transport discovery

`kmesh::config::Config` contains `server_url`, profile and data directory, TLS roots and optional HTTP CONNECT proxy, plus the target's local SSH address and connect timeout. The client and agent use the same HTTPS control origin. No STUN server list, UDP bind override, QUIC certificate, or data-relay URL is configured by the client.

`GET /v1/transport` returns `TransportInfo { private_relay_url: Option<String>, qad_port: u16 }` over the trusted kmesh HTTPS connection. A configured private relay uses that exact HTTPS origin and the server's bound QAD UDP port. `--disable-private-relay` makes `private_relay_url` absent. In that configuration, new SSH attempts use Iroh's SDK default relay set. The server continues to handle online login, refresh, authorization, ticket issuance, and activation in both modes.

The target agent persists one stable Iroh `SecretKey` with its enrollment credentials. It creates the private endpoint when the server prepares the first private session and creates a separate public-default endpoint only when asked to prepare a public session. Both endpoints use the enrolled identity; each mode has its own endpoint, relay map, accept loop, and active streams. Control reconnects do not replace established SSH streams.

## Authentication and authorization

User login supports password and OpenSSH SSHSIG public-key challenges. Passwords use Argon2id hashes. User access JWTs have a 15-minute lifetime; refresh credentials rotate and are stored server-side as hashes. Device agent credentials are separate from user credentials.

JWT identity does not cache target permissions. The server reads current user status, login-session status, target status, role bindings, and `ssh_connect` grants when opening and activating a session. The signed `TunnelTicketClaims` bind the session, user, login session, target, client and target EndpointIds, relay mode, issuer, audience, and expiry. The agent validates the ticket and its relay mode before accepting a connection. An activated SSH stream continues to completion after later permission changes or control-plane loss; opening a new stream requires the kmesh server to be available.

## Connection control flow

The client creates an ephemeral Iroh identity for each attempt and sends `Open { session_id, target_id, client_endpoint_id, relay_mode }` on `/v1/connect`. The server checks current RBAC, creates a pending session and signed ticket, and sends `Prepare { session_id, relay_mode }` to the online agent.

The agent prepares the requested endpoint, waits for its selected relay connection to become online, and returns `AgentReady` with its `EndpointAddr`. The server validates its EndpointId against the registered target and validates relay URLs against that mode's allowlist. It then sends `Offer` to the agent. The agent verifies the ticket, checks the address against the signed relay mode and trusted `/v1/transport` response, registers the pending peer identity, and responds with `OfferReady`. Only then does the server send the offer to the client.

The client verifies the ticket and the mode-specific relay allowlist, establishes an Iroh connection, opens one bidirectional stream, and sends the signed ticket over that stream. The agent verifies the peer EndpointId and stream ticket, then reports `IrohReady`. The server rechecks current RBAC in a transaction and sends `Activated` only after the pending-to-active transition succeeds. The agent connects to its local `ssh.address` only after activation.

The control protocol carries fixed relay modes: `Private` and `PublicDefault`. If no private relay is configured, the first attempt uses `PublicDefault`. If a private attempt fails with a classified network error, the proxy closes that pending session, refreshes/reconnects to the kmesh control service, and opens a new public-default session with a fresh session ID and client endpoint identity. That second `Open` repeats server authorization and ticket issuance. TLS trust, relay authentication, proxy authentication, ticket, identity, permission, and configuration errors do not trigger the public retry. Public mode accepts only Iroh SDK default relay URLs; private mode accepts only the configured self-hosted relay URL. Direct IP candidates remain available in either mode.

## Data stream and path reporting

One OpenSSH `ProxyCommand` process maps to one Iroh QUIC bidirectional stream. The stream preserves EOF, half-close, reset, backpressure, and final-byte acknowledgement. Normal completion sends FIN and waits for the peer to acknowledge the final SSH bytes; cancellation resets the stream. The local SSH socket uses `TCP_NODELAY`.

Iroh selects and can upgrade its network path while the stream remains active. The proxy reports the selected path and later path changes to stderr; stdout is reserved for OpenSSH byte transport. The path is either P2P direct or an Iroh relay. Public-default relay use carries SSH data through the SDK's default relay infrastructure; kmesh does not provide or publish that public relay service.

## Server listeners and storage

`kmesh server run` serves HTTPS control and, unless `--disable-private-relay` is supplied, the embedded Iroh HTTP relay on the same TCP listener (default `0.0.0.0:9443`). The Iroh QAD listener defaults to UDP `0.0.0.0:3478`. The server uses its configured TLS certificate for HTTPS and QAD.

SQLite WAL stores users, keys, roles, permissions, targets, login sessions, and tunnel-session state. This implementation expects the current schema in a fresh database directory. It does not migrate the previous STUN/Quinn/WSS-data schema. Keep that earlier database unchanged and initialize the Iroh service in a separate empty `--data-dir`.
