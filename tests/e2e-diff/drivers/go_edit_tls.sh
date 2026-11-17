#!/usr/bin/env bash
# E5/E6: TLS certificate edit against a real Nginx front.
#
# E5 proves the success path (write, reload, live handshake, renewal target,
# previous pair in the backup, Xray untouched). E6 proves the guard rejects a
# bad pair before any write and that a handshake failure after the write rolls
# the whole transaction back.
#
# Usage: bash go_edit_tls.sh <scenario E5|E6> idleleo xray config edit ...
set -u

EID="${1:-E5}"
shift || true
DOMAIN="${E2E_DOMAIN:-example.com}"
OUT="${E2E_OUT:?E2E_OUT required}"
DIR="$OUT/edit"
mkdir -p "$DIR"

# The installer and the edit command both refuse real-root writes without this
# container-only acknowledgement (same rule go_install.sh follows).
export IDLELEO_ALLOW_SYSTEM_WRITES="${IDLELEO_ALLOW_SYSTEM_WRITES:-I_ACCEPT_CONTAINER_ONLY}"

IDLELEO=/usr/local/bin/idleleo
CFG=/etc/idleleo/conf/xray/config.json
JOBS=/etc/idleleo/schedule/jobs.json
NGDIR=/etc/idleleo/conf/nginx
CERTDIR=/etc/idleleo/cert
OLDCERT="$CERTDIR/xray.crt"
OLDKEY="$CERTDIR/xray.key"
BACKUPROOT=/etc/idleleo/backup
DROPIN=/etc/systemd/system/nginx.service.d/e2e-noop-reload.conf

sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
line_at() { awk -v n="$(($2 + 1))" 'NR == n {print}' "$1" 2>/dev/null; }

served_pem() {
  openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -showcerts </dev/null 2>/dev/null |
    awk '/BEGIN CERTIFICATE/{on=1} on{print} /END CERTIFICATE/{if(on) exit}'
}

fnv() { openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//'; }
served_fp_now() { served_pem | fnv; }

# Nginx reload is asynchronous: the master returns before the new workers take
# over, so the snapshot waits for the served leaf to settle.
wait_served() { # $1 = expected fingerprint, $2 = seconds
  local want=$1 limit=$(($2 * 5)) i=0
  while [ "$i" -lt "$limit" ]; do
    [ "$(served_fp_now)" = "$want" ] && return 0
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

snap() { # $1 = tag
  local d="$DIR/state-$1"
  mkdir -p "$d"
  { sha "$CFG"; } >"$d/config.sha"
  { sha "$JOBS"; } >"$d/jobs.sha"
  for f in 00-xray.conf 01-xray-80.conf 02-xray-server.conf; do
    { sha "$NGDIR/$f"; } >"$d/nginx-$f.sha"
  done
  { sha "$OLDCERT"; sha "$OLDKEY"; } >"$d/oldpair.sha"
  systemctl show xray -p MainPID -p ActiveEnterTimestamp >"$d/xray.show" 2>/dev/null
  systemctl is-active xray >"$d/xray.active" 2>/dev/null
  systemctl is-active nginx >"$d/nginx.active" 2>/dev/null
  cp -f "$JOBS" "$d/jobs.json" 2>/dev/null || :
  served_pem >"$d/served.pem"
  fnv <"$d/served.pem" >"$d/served.fp"
  ls -1d "$BACKUPROOT"/edit-* 2>/dev/null | sort >"$d/backups.txt" || :
}

pair_for() { # $1 = file stem, $2 = domain
  local tmp
  tmp="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$2" \
    -addext "subjectAltName=DNS:$2" -keyout "$tmp/new.key" -out "$tmp/new.crt" >/dev/null 2>&1
  install -m 0640 "$tmp/new.crt" "$CERTDIR/$1.crt"
  install -m 0640 "$tmp/new.key" "$CERTDIR/$1.key"
  rm -rf "$tmp"
}

run_edit() { # $@ = idleleo xray config edit ...
  "$IDLELEO" "${@:2}" >"$DIR/edit.json" 2>"$DIR/edit.err"
  echo $? >"$DIR/edit.rc"
}

idleleo_ok() {
  "$IDLELEO" "$@" >"$DIR/harness.log" 2>&1
}

# 1. A renewal job must exist so the edit has a target to follow.
idleleo_ok schedule install --interval 3600 --cert-domain "$DOMAIN" \
  --cert-out etc/idleleo/cert/xray.crt --cert-key-out etc/idleleo/cert/xray.key \
  --container --json ||
  echo "schedule install failed; see harness.log" >>"$DIR/edit.err"
snap pre

CHECKS='{}'
FAIL_MSG=""
EDIT_RC=99
BEFORE_SHA="$(cat "$DIR/state-pre/config.sha")"
AFTER_SHA="$BEFORE_SHA"

if [ "$EID" = "E5" ]; then
  pair_for e5-new "$DOMAIN"
  NEWCERT="$CERTDIR/e5-new.crt"
  NEWKEY="$CERTDIR/e5-new.key"
  NEWFP="$(fnv <"$NEWCERT")"
  run_edit "$@"
  EDIT_RC="$(cat "$DIR/edit.rc")"
  wait_served "$NEWFP" 10 || true
  snap post
  cp -f "$DIR/state-post/jobs.json" "$DIR/jobs-after.json" 2>/dev/null || :
  BK="$(tail -n 1 "$DIR/state-post/backups.txt" 2>/dev/null || true)"
  if [ -n "$BK" ] && [ -d "$BK" ]; then cp -a "$BK" "$DIR/backup"; fi
  AFTER_SHA="$(cat "$DIR/state-post/config.sha")"

  python3 - "$DIR" "$DOMAIN" "$NEWCERT" "$NEWKEY" "$NEWFP" "$EDIT_RC" <<'PY'
import json, os, sys
d, domain, newcert, newkey, newfp, rc = sys.argv[1:7]
def read(p, default=""):
    try:
        return open(p).read().strip()
    except OSError:
        return default
def line(p, n=0):
    v = read(p).splitlines()
    return v[n] if len(v) > n else ""
pre, post = os.path.join(d, "state-pre"), os.path.join(d, "state-post")
try:
    rep = json.load(open(os.path.join(d, "edit.json")))
except Exception:
    rep = {}
err = read(os.path.join(d, "edit.err"))
frag = read("/etc/idleleo/conf/nginx/00-xray.conf")
jobs = {}
try:
    jobs = json.load(open(os.path.join(d, "jobs-after.json")))
except Exception:
    pass
bk = os.path.join(d, "backup")
checks = {
    "editRcZero": rc == "0",
    "probeOk": rep.get("tlsProbe") == "ok" and rep.get("tlsServerName") == domain,
    "tlsVersion13": rep.get("tlsVersion") == "TLS 1.3",
    "wireCertMatches": line(os.path.join(post, "served.fp")) == newfp,
    "fragmentUpdated": newcert in frag and newkey in frag,
    "backupHasOldCert": False,
    "backupHasOldKey": False,
    "scheduleUpdated": jobs.get("certDomain") == domain
        and jobs.get("certFile") == newcert.lstrip("/")
        and jobs.get("certKeyFile") == newkey.lstrip("/"),
    "runtimeUnchanged": line(os.path.join(pre, "config.sha")) == line(os.path.join(post, "config.sha")),
    "xrayNotRestarted": read(os.path.join(pre, "xray.show")) == read(os.path.join(post, "xray.show")),
    "servicesActive": read(os.path.join(post, "xray.active")) == "active"
        and read(os.path.join(post, "nginx.active")) == "active",
}
# backup pair is compared by the shell below (hash of the pre-edit files)
checks["backupHasOldCert"] = read(os.path.join(d, "backup-cmp"), "mismatch") == "ok"
json.dump({"checks": checks, "wanted": sorted(checks), "allPassed": all(checks.values()),
           "editRc": int(rc), "beforeSha": "", "afterSha": "", "error": err[-2000:]},
          open(os.path.join(d, "checks.json"), "w"), indent=2, sort_keys=True)
PY
  # Compare the backup's saved pair with the pre-edit files.
  if [ -f "$DIR/backup/tls-cert.pem" ] &&
    [ "$(sha "$DIR/backup/tls-cert.pem")" = "$(line_at "$DIR/state-pre/oldpair.sha" 0)" ] &&
    [ "$(sha "$DIR/backup/tls-key.pem")" = "$(line_at "$DIR/state-pre/oldpair.sha" 1)" ]; then
    echo ok >"$DIR/backup-cmp"
  else
    echo mismatch >"$DIR/backup-cmp"
  fi
  # re-run the check block now that backup-cmp exists
  python3 - "$DIR" <<'PY'
import json, os, sys
d = sys.argv[1]
p = os.path.join(d, "checks.json")
c = json.load(open(p))
ok = open(os.path.join(d, "backup-cmp")).read().strip() == "ok"
c["checks"]["backupHasOldCert"] = ok
c["checks"]["backupHasOldKey"] = ok
c["allPassed"] = all(c["checks"].values())
json.dump(c, open(p, "w"), indent=2, sort_keys=True)
PY
else
  # ---- E6a: a pair that does not cover the new domain must not touch disk.
  GUARD_RC_BEFORE="$EDIT_RC"
  "$IDLELEO" xray config edit --domain other.test --yes --container --json \
    >"$DIR/guard.json" 2>"$DIR/guard.err"
  echo $? >"$DIR/guard.rc"
  GUARD_RC="$(cat "$DIR/guard.rc")"
  snap guard

  # ---- E6b: a valid pair plus a reload that silently does not apply it.
  pair_for e6-new "$DOMAIN"
  mkdir -p "$(dirname "$DROPIN")"
  # ExecReload is a multi-value directive: the empty assignment resets the
  # unit's command first, otherwise systemd runs both and the reload still
  # happens.
  printf '[Service]\nExecReload=\nExecReload=/bin/true\n' >"$DROPIN"
  systemctl daemon-reload
  run_edit "$@"
  EDIT_RC="$(cat "$DIR/edit.rc")"
  snap failed
  BK="$(tail -n 1 "$DIR/state-failed/backups.txt" 2>/dev/null || true)"
  if [ -n "$BK" ] && [ -d "$BK" ]; then cp -a "$BK" "$DIR/backup"; fi
  # Restore real Nginx reloading and let it settle before the final snapshot.
  rm -f "$DROPIN"
  systemctl daemon-reload
  systemctl reload nginx >/dev/null 2>&1 || true
  wait_served "$(cat "$DIR/state-pre/served.fp")" 10 || true
  snap post
  cp -f "$DIR/state-post/jobs.json" "$DIR/jobs-after.json" 2>/dev/null || :
  AFTER_SHA="$(cat "$DIR/state-post/config.sha")"
  ERR="$(cat "$DIR/edit.err")"

  GUARD_OK=0
  if [ "$GUARD_RC" != "0" ] && grep -q 'does not cover' "$DIR/guard.err"; then GUARD_OK=1; fi
  ZERO_WRITES=1
  for k in config.sha jobs.sha oldpair.sha nginx-00-xray.conf.sha nginx-01-xray-80.conf.sha nginx-02-xray-server.conf.sha; do
    [ "$(cat "$DIR/state-pre/$k")" = "$(cat "$DIR/state-guard/$k")" ] || ZERO_WRITES=0
  done
  [ "$(wc -l <"$DIR/state-pre/backups.txt")" = "$(wc -l <"$DIR/state-guard/backups.txt")" ] || ZERO_WRITES=0

  if [ -f "$DIR/backup/tls-cert.pem" ] &&
    [ "$(sha "$DIR/backup/tls-cert.pem")" = "$(line_at "$DIR/state-pre/oldpair.sha" 0)" ] &&
    [ "$(sha "$DIR/backup/tls-key.pem")" = "$(line_at "$DIR/state-pre/oldpair.sha" 1)" ]; then
    echo ok >"$DIR/backup-cmp"
  else
    echo mismatch >"$DIR/backup-cmp"
  fi

  python3 - "$DIR" "$GUARD_RC" "$GUARD_OK" "$ZERO_WRITES" "$EDIT_RC" "$ERR" <<'PY'
import json, os, sys
d, guard_rc, guard_ok, zero, rc, err = sys.argv[1:7]
def line(p):
    try:
        return open(p).read().strip()
    except OSError:
        return ""
def same(name):
    return line(os.path.join(d, "state-pre", name)) == line(os.path.join(d, "state-post", name))
failed = os.path.join(d, "state-failed")
same_failed = lambda n: line(os.path.join(d, "state-pre", n)) == line(os.path.join(failed, n))
checks = {
    "guardRejected": guard_ok == "1",
    "guardZeroWrites": zero == "1",
    "rollbackRcNonZero": rc != "0",
    "probeFailureRecorded": "serves a certificate that differs from the configured file" in err,
    "configRestored": same("config.sha") and same_failed("config.sha"),
    "nginxRestored": all(same_failed("nginx-" + f + ".sha")
                         for f in ("00-xray.conf", "01-xray-80.conf", "02-xray-server.conf"))
                    and all(same("nginx-" + f + ".sha")
                            for f in ("00-xray.conf", "01-xray-80.conf", "02-xray-server.conf")),
    "scheduleRestored": same("jobs.sha") and same_failed("jobs.sha"),
    "servedCertRestored": line(os.path.join(d, "state-pre", "served.fp")) == line(os.path.join(d, "state-post", "served.fp")),
    "backupHasOldPair": line(os.path.join(d, "backup-cmp")) == "ok",
    "servicesActive": line(os.path.join(d, "state-post", "xray.active")) == "active"
                      and line(os.path.join(d, "state-post", "nginx.active")) == "active",
}
out = {"checks": checks, "wanted": sorted(checks), "allPassed": all(checks.values()),
       "editRc": int(rc), "guardRc": int(guard_rc),
       "failurePoint": "tls-probe: served certificate mismatch",
       "beforeSha": line(os.path.join(d, "state-pre", "config.sha")),
       "afterSha": line(os.path.join(d, "state-post", "config.sha")),
       "error": err[-2000:]}
json.dump(out, open(os.path.join(d, "checks.json"), "w"), indent=2, sort_keys=True)
PY
fi

# Normalize the report fields every edit scenario is expected to carry.
python3 - "$DIR" "$BEFORE_SHA" "$AFTER_SHA" "$EDIT_RC" <<'PY'
import json, os, sys
d, before, after, rc = sys.argv[1:5]
p = os.path.join(d, "checks.json")
try:
    c = json.load(open(p))
except Exception:
    c = {"checks": {}, "allPassed": False}
c.setdefault("beforeSha", before)
c.setdefault("afterSha", after)
c.setdefault("editRc", int(rc))
c["beforeSha"] = c.get("beforeSha") or before
c["afterSha"] = c.get("afterSha") or after
json.dump(c, open(p, "w"), indent=2, sort_keys=True)
PY

exit 0
