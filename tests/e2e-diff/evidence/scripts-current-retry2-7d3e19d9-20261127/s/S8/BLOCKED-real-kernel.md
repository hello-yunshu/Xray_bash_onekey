# S8 real-kernel apply: BLOCKED (host kernel)

`idleleo tcp plan/apply/rollback` was verified end to end in the disposable
sandbox. Applying to the live kernel needs a VPS whose kernel lists `bbr` and
exposes `net.core.default_qdisc`; the Docker/OrbStack kernel used here has
neither, and the CLI correctly refuses instead of installing a kernel.
Unblock on a real VPS with `idleleo tcp apply --profile bbr-fq --confirm`.
