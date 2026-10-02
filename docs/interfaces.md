# Shared interfaces

This document freezes the first implementation boundary between the server, transport, and client workstreams. HTTP routes use JSON from `kmesh::protocol`; WebSocket control uses `ControlMessage`. SSH destinations stay in the target agent's local configuration.

## Configuration and identity

`kmesh::config::Config` owns the profile name, server URL, data directory, TLS roots/proxy, local SSH socket address, and STUN/probe settings. An empty `stun.servers` means the client derives its STUN endpoint from the configured server host at UDP port 3478. `identity` creates independent Ed25519 keypairs for user access JWTs and tunnel tickets, creates a persistent self-signed target QUIC certificate, and encodes/validates each token type against its own audience. Decoders require `exp`, `iat`, `aud`, and `iss`; callers provide the expected issuer. Ticket verification allows 2 seconds of expiry leeway, while user access tokens use zero leeway. `TokenKeySet::ticket_verification_key_pem()` exposes the ticket verification key for enrollment and offers.

## HTTP JSON types

- Login: `PasswordLoginRequest`, `PublicKeyChallengeRequest`, `PublicKeyChallenge`, `PublicKeyLoginRequest`, and `RefreshRequest`; success returns `LoginTokens`.
- `GET /v1/me` returns `MeView { user, roles }`. Target listing returns `TargetView { target_id, name, enabled, online }`; the stable ID controls authorization, the name is display-only, and enabled/online report distinct management and connection states.
- Admin operations are sent as `AdminRequest` to `POST /v1/admin`. `AdminOperation` is tagged by `operation` with payload in `data`; list operations return typed `Users`, `Roles`, `Keys`, `UserRoles`, `Grants`, and `Targets`, while target creation/enrollment issue returns a one-time enrollment token.
- Agent enrollment sends `target_id`, its one-time enrollment token, and locally generated certificate DER. The agent generates the certificate for the selected stable target ID and retains its private key; the response returns `target_id`, `agent_token`, and `ticket_public_key_pem` obtained over the authenticated server TLS connection. `AgentCredentials` persists those values with the local certificate and private key.
- `TunnelTicketClaims` binds session, user, login session, target, client ephemeral public key, target certificate fingerprint, issuer, audience, issue time, and expiry. Offers include the 32-byte base64 probe token, target certificate DER, and ticket verification key PEM.
- Probe tokens are 32 random bytes encoded with URL-safe base64 without padding and used as the HMAC key for the UDP probe exchange. The client ephemeral Ed25519 public key is encoded as base64 raw key bytes.
- `QuicChallenge.nonce` is a 32-byte random nonce encoded as URL-safe base64 without padding. The client signs UTF-8 `kmesh-quic-auth\0{ticket}\0{nonce}` using its ephemeral Ed25519 key; `DirectAuthentication` carries the ticket and base64 signature.

## Control WebSocket

`ControlMessage` is shared by `/v1/connect` and `/v1/agent/control`. Client opens carry only session/target identity and the ephemeral key. Server forwards an `Offer` to the target, then routes candidate exchange, probe observations, QUIC readiness, relay selection, activation, cancellation, and errors. The server rechecks access when activating a path. No control message carries an SSH host or port. Relay WebSockets use `RelayConnectQuery { session_id, peer }` on the authenticated `/v1/relay` handshake with the user or target bearer credential in the `Authorization` header.

The selected data path is reported with `Activated.path` (`quic` or `relay`). QUIC and relay each carry one bidirectional byte stream for one SSH `ProxyCommand` process. Relay WebSocket pairing binds the session at the authenticated control/relay URL; relay data frames do not repeat session IDs.

## Transport API

- `UdpAttempt::bind`, `gather`, and `probe` prepare an attempt; `into_quic_client` and `into_quic_server` transfer its bound UDP socket to Quinn.
- `QuicByteStream` and `RelayByteStream` implement `AsyncRead + AsyncWrite`. `QuicAcceptor::accept` yields a `QuicByteStream` for each incoming SSH stream.
- `connect_wss` returns the raw WebSocket used by control and relay clients. `RelayByteStream::from_ws` wraps relay data WebSockets.
- Relay binary frames use `[0] + data` for bytes, `[1]` for FIN, and `[2] + reason` for RESET. A WebSocket close ends the whole relay stream.
- HTTP and WSS share network settings for HTTP/HTTPS CONNECT, Basic proxy authentication, and custom CA certificates.
