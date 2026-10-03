# Live verification status

The current Iroh-based implementation has not been run against the public server or `target-1`. The historical report in [`verify_live_report.md`](verify_live_report.md) records an earlier STUN/Quinn/WSS-data build and does not validate this implementation.

The earlier live-verification program used retired STUN and relay interfaces and has been removed. Reusing that program against the Iroh release would make unsupported protocol and deployment assumptions. A new live verification must follow a separate review of the fresh database directory, server binary and unit, target agent identity, and operator-managed service transition.
