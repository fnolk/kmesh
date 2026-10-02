# Shared interfaces

This document freezes the first implementation boundary between the server, transport, and client workstreams. HTTP routes use JSON from `kmesh::protocol`; WebSocket control uses `ControlMessage`. SSH destinations stay in the target agent's local configuration.

## Configuration and identity

`kmesh::config::Config` owns the profile name, server URL, data directory, TLS roots/proxy, local SSH socket address, and STUN/probe settings. `identity` creates independent Ed25519 keypairs for user access JWTs and tunnel tickets, creates a persistent self-signed target QUIC certificate, and encodes/validates each token type against its own audience.

## HTTP JSON types

- Login: `PasswordLoginRequest`, `PublicKeyChallengeRequest`, `PublicKeyChallenge`, `PublicKeyLoginRequest`, and `RefreshRequest`; success returns `LoginTokens`.
- Target listing returns `TargetView`, whose `target_id` is the stable authorization identity and whose `name` is display-only.
- Admin operations are sent as `AdminRequest` to `POST /v1/admin`. `AdminOperation` is tagged by `operation` with payload in `data`; target creation returns `AdminResponse::TargetCreated` with its one-time enrollment token.
- Agent enrollment sends its one-time enrollment token and locally generated certificate DER. The agent retains its private key; the response returns only `target_id` and `agent_token`.
- `TunnelTicketClaims` binds session, user, login session, target, client ephemeral public key, target certificate fingerprint, issuer, audience, issue time, and expiry.

## Control WebSocket

`ControlMessage` is shared by `/v1/connect` and `/v1/agent/control`. Client opens carry only session/target identity and the ephemeral key. Server forwards an `Offer` to the target, then routes candidate exchange, probe observations, QUIC readiness, relay selection, activation, cancellation, and errors. The server rechecks access when activating a path. No control message carries an SSH host or port.

The selected data path is reported with `Activated.path` (`quic` or `relay`). QUIC and relay each carry one bidirectional byte stream for one SSH `ProxyCommand` process. Relay WebSocket pairing binds the session at the authenticated control/relay URL; relay data frames do not repeat session IDs.

## Transport API

- `UdpAttempt::bind`, `gather`, and `probe` prepare an attempt; `into_quic_client` and `into_quic_server` transfer its bound UDP socket to Quinn.
- `QuicByteStream` and `RelayByteStream` implement `AsyncRead + AsyncWrite`. `QuicAcceptor::accept` yields a `QuicByteStream` for each incoming SSH stream.
- `connect_wss` returns the raw WebSocket used by control and relay clients. `RelayByteStream::from_ws` wraps relay data WebSockets.
- Relay binary frames use `[0] + data` for bytes, `[1]` for FIN, and `[2] + reason` for RESET. A WebSocket close ends the whole relay stream.
- HTTP and WSS share network settings for HTTP/HTTPS CONNECT, Basic proxy authentication, and custom CA certificates.
