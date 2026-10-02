# Kmesh vendor notice

This directory contains the `iroh-relay` 1.3.0 crate from the upstream iroh
v1.3.0 release (`n0-computer/iroh`, commit `0072d7d`). The upstream source is
available at <https://github.com/n0-computer/iroh/tree/v1.3.0/iroh-relay>.

Kmesh adds `percent-encoding` as a direct dependency and changes
`src/client/tls.rs`: HTTP CONNECT proxy credentials are percent-decoded from
URL userinfo before use, and the `Proxy-Authorization: Basic` value uses RFC
7617 standard Base64. The regression test sends a real CONNECT request to a
loopback HTTP proxy and verifies the received header decodes to the original
credentials, including credentials whose Base64 contains `+` and `/`.

Upstream copyright and license files are retained. The crate declares
`MIT OR Apache-2.0`; `LICENSE-MIT`, `LICENSE-APACHE`, and the upstream
`LICENSE-BSD3` attribution for derived Tailscale code are included here.
