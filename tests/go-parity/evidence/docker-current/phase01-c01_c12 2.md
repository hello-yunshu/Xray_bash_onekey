# Phase 01 C01-C12 evidence

- Date: 2026-11-07T14:52:27Z
- Binary: /tmp/idleleo (sha256 d34d36ab95deeb9a811f15e0f44c8f1f4d6a6007f9ddbb8aa6480157275abd5c)
- Image: idleleo-phase01-test:1.24 sha256:8af4eaa68338d882c32104e30d347f575f5c23730c6249fb82b78bebd3bab6c5
- Arch: aarch64; kernel: 7.2.12-orbstack-00394-gbecdd6130068
- Xray: Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/arm64) (sha256 5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328)
- Pin: 0fa7052e51b9bd7e6ffb46bc86befb006034da3c; install.sh sha256: a8e4d850da40295303785d17bc3ee629574932b56aef9ae3905baf4e6797358c
- Result: 35/35 passed, 0 failed

| ID | Check | Expected | Actual | Pass | Detail |
|---|---|---|---|---|---|
| C01.1 | version | 0 | 0 | PASS | empty root unchanged |
| C01.2 | status on empty root | 3 | 3 | PASS | not-installed exit, zero files |
| C01.3 | status fixture | 0 | 0 | PASS | sha unchanged |
| C01.4 | config inspect | 0 | 0 | PASS | sha unchanged |
| C01.5 | show non-root sandbox | 0 | 0 | PASS | sha unchanged |
| C02.1 | no TTY does not hang | 2 | 2 | PASS | explained exit 2 |
| C02.2 | TERM=dumb no ANSI | 0 | 0 | PASS | no ESC bytes |
| C03.corrupt | corrupt metadata | 4 | 4 | PASS | classified exit |
| C03.schema | schema metadata | 5 | 5 | PASS | classified exit |
| C03.unsupported | unsupported metadata | 12 | 12 | PASS | classified exit |
| C03.secret | secret metadata | 4 | 4 | PASS | classified exit |
| C03.missing | missing metadata | 3 | 3 | PASS | no files created |
| C04.1 | custom dns/routing/top-level | 0 | 0 | PASS | sha unchanged |
| C04.2 | show derives authority | 0 | 0 | PASS | no rewrite |
| C04.reality-direct | fixture reality-direct read-only | 0 | 0/0 | PASS | parsed, sha unchanged |
| C04.tls-multi | fixture tls-multi read-only | 0 | 0/0 | PASS | parsed, sha unchanged |
| C04.custom-dns-routing | fixture custom-dns-routing read-only | 0 | 0/0 | PASS | parsed, sha unchanged |
| C05.1 | status reports drift | 0 | 0 | PASS | read-only drift report |
| C05.2 | change refuses stale baseline | 7 | 7 | PASS | no journal write |
| C06 | validator rejects | 8 | 8 | PASS | target bytes unchanged |
| C07 | injected write failure | 13 | 13 | PASS | target untouched |
| C08.1 | service apply failure | 9 | 9 | PASS | restored, only apply invoked |
| C08.2 | injected service failure | 9 | 9 | PASS | restored |
| C06.real | real xray validator | 0 | 0 | PASS | Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/arm64); xray-test=0; committed |
| C09 | lock contention | 7 | 7 | PASS | no write under lock |
| C10.1 | non-root status | 0 | 0 | PASS | read-only |
| C10.2 | non-root illegal command | 2 | 2 | PASS | no mutation |
| C10.3 | non-root change refused | nonzero | 2 | PASS | no write |
| C11.1 | linux/amd64 build | 0 | 0 | PASS | bytes=10224171 |
| C11.2 | linux/arm64 build | 0 | 0 | PASS | bytes=9728187 |
| C11.3 | current-arch binary runs | 0 | 0 | PASS | aarch64 |
| C12.1 | install.sh bytes match pin | a8e4d850da40295303785d17bc3ee629574932b56aef9ae3905baf4e6797358c | a8e4d850da40295303785d17bc3ee629574932b56aef9ae3905baf4e6797358c | PASS | pin 0fa7052e51b9bd7e6ffb46bc86befb006034da3c |
| C12.2 | product code diff empty | empty | empty | PASS | no Bash core change |
| C12.3 | Go does not install over Bash entry | empty |  | PASS | legacy path absent |
| C12.4 | published Bash pin still loads | 3.3.6 | 3.3.6 | PASS | published pin untouched |
