# Cold restore real-machine evidence (relay)

- run-id: `bc13-8ff-1128`
- commit: `8ff26917e3e381d4023b7319d5405f7ba871f289`
- image id: `sha256:828040e78d98d640e238b799f1f1c4441a719307e1e80d0b57db89cb9556e5bc`
- source driver rc: 0
- target driver rc: 1
- archive sha256: `2074b147a41a5d8e3dc52598a5ebe7ca992efba05a37b723cd6570df7380714b`

- **PASS** [source] source client connected through Bash-managed services
- **PASS** [source] Bash archive created, tar listing valid, archive mode 0600
- **PASS** [target] fresh target Bash restore preserved managed state bytes
- **FAIL** [target] restored mode/owner matches (etc_idleleo_cert_thirdparty.crt.mode-owner)
- **FAIL** [target] restored mode/owner matches (etc_idleleo_cert_thirdparty.key.mode-owner)
- **PASS** [target] restored mode/owner matches (etc_idleleo_conf_nginx_relay-stream.conf.mode-owner)
- **PASS** [target] restored mode/owner matches (etc_idleleo_conf_thirdparty-note.txt.mode-owner)
- **PASS** [target] restored mode/owner matches (etc_idleleo_install.sh.mode-owner)
- **PASS** [target] restored mode/owner matches (etc_systemd_system_nginx.service.mode-owner)
- **PASS** [target] restored mode/owner matches (usr_local_nginx_sbin_nginx.mode-owner)
- **PASS** [target] restored validators, services, and real client connection succeeded
