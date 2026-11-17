# P1 smoke

run-id: `20261113-2342-2078a45`

| scenario | side | install rc | manifest | runtime | L4 |
|---|---|---|---|---|---|
| M1 | bash | 0 | yes | yes | PASS |
| M1 | go | 0 | yes | yes | PASS |
| M4 | bash | 0 | yes | yes | PASS |
| M4 | go | 0 | yes | yes | PASS |

L4 uses a real client container (separate netns) and one proxied
HTTP request to http://example.com/; the server config blackholes
private/loopback targets, so a loopback origin cannot be used.
