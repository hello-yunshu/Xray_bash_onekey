# S7 issuance: BLOCKED (external)

`download + install + --version/--help` passed in this run. Real issuance and
renewal through acme.sh need:

- a domain whose A/AAAA record points at this host, and
- a public ACME directory that can reach it over HTTP-01/TLS-ALPN.

Containers here have no public inbound, so this step cannot be executed
honestly. Unblock with a real VPS + real domain and re-run the same commands
with `IDLELEO_ACME_LEGACY=1`.
