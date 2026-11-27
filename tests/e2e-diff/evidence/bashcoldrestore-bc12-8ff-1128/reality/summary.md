# Cold restore real-machine evidence (reality)

- run-id: `bc12-8ff-1128`
- commit: `8ff26917e3e381d4023b7319d5405f7ba871f289`
- image id: `sha256:828040e78d98d640e238b799f1f1c4441a719307e1e80d0b57db89cb9556e5bc`
- source driver rc: 0
- target driver rc: 0
- archive sha256: `577fbec3a2ba86212c326ff0999a0abce11306b133526833a4e764064fd88704`

- **PASS** [source] source client connected through Bash-managed services
- **PASS** [source] Bash archive created, tar listing valid, archive mode 0600
- **PASS** [target] fresh target Bash restore preserved managed state bytes
- **PASS** [target] fresh target Bash restore preserved managed state mode and owner
- **PASS** [target] restored validators, services, and real client connection succeeded
