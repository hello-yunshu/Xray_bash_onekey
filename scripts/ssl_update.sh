#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="${IDLELEO_CERT_GROUP:-idleleo-nginx}"
idleleo_dir="${IDLELEO_DIR:-/etc/idleleo}"
nginx_systemd_file="${IDLELEO_NGINX_UNIT:-/etc/systemd/system/nginx.service}"
xray_systemd_file="${IDLELEO_XRAY_UNIT:-/etc/systemd/system/xray.service}"
ssl_chainpath="${IDLELEO_CERT_DIR:-${idleleo_dir}/cert}"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
acme_sh_dir="${IDLELEO_ACME_HOME:-${HOME:-/root}/.acme.sh}"
running_file="${idleleo_dir}/ssl_update_running"
running_file_max_age_minutes=120
# Shared with install.sh / auto_update.sh / geo_update.sh: certificate renewal
# must not race an Nginx or Xray upgrade that restarts the same units.
update_lock_file="${XRAY_UPDATE_LOCK_FILE:-/run/lock/idleleo-update.lock}"

host=""
# S7-4: renewal is native (`idleleo xray cert renew`) unless the operator opts
# into the one-release acme.sh fallback. The native path needs Nginx to keep
# serving the HTTP-01 webroot, so it never stops the unit.
acme_legacy="${IDLELEO_ACME_LEGACY:-0}"
# This script renews an existing production certificate, so production must be
# explicit. The CLI itself defaults to staging.
if [[ -n "${IDLELEO_ACME_DIRECTORY:-}" ]]; then
    acme_dir_args=(--directory "${IDLELEO_ACME_DIRECTORY}")
else
    acme_dir_args=(--production)
fi
idleleo_bin=""
# Nginx state bookkeeping. "yes" means THIS run stopped a unit that was
# running before; it is the only condition that ever starts Nginx again.
nginx_stopped="no"
lock_held="no"

ssl_log() {
    printf '%s\n' "$*" >&2
}

release_locks() {
    if [[ "${lock_held}" == "yes" ]]; then
        flock -u 9 2>/dev/null || true
        exec 9>&-
        lock_held="no"
    fi
    [[ -d "${running_file}" ]] && rm -rf "${running_file}"
    return 0
}

acquire_locks() {
    if [[ -d "${running_file}" ]] && [[ -n $(find "${running_file}" -maxdepth 0 -mmin +"${running_file_max_age_minutes}" 2>/dev/null) ]]; then
        ssl_log "Removing stale ssl update lock: ${running_file}"
        rm -rf "${running_file}"
    fi

    if ! mkdir "${running_file}" 2>/dev/null; then
        ssl_log "Previous ssl update process is still running!"
        return 1
    fi
    printf '%s\n' "$$" >"${running_file}/pid"

    if [[ "${IDLELEO_UPDATE_LOCK_HELD:-0}" == 1 ]]; then
        return 0
    fi
    # util-linux flock is absent on some environments; the mkdir lock above
    # still keeps a single renewal running, so this stays best-effort.
    command -v flock >/dev/null 2>&1 || return 0
    mkdir -p "$(dirname "${update_lock_file}")" 2>/dev/null || true
    if [[ ! -w "$(dirname "${update_lock_file}")" ]]; then
        ssl_log "Shared update lock directory is not writable: $(dirname "${update_lock_file}")"
        return 1
    fi
    exec 9>"${update_lock_file}"
    if ! flock -n 9; then
        ssl_log "Another update process is holding ${update_lock_file}"
        return 1
    fi
    lock_held="yes"
    return 0
}

# All conditions that can be verified without touching any service are checked
# here, before Nginx is stopped, so a missing prerequisite never takes the
# reverse proxy down.
preflight_checks() {
    if [[ ! -f "${xray_install_config_file}" ]]; then
        ssl_log "Config file not found: ${xray_install_config_file}"
        return 1
    fi

    host=$(jq -r '.host // empty' "${xray_install_config_file}" 2>/dev/null)
    if [[ -z "${host}" || "${host}" == "null" ]]; then
        ssl_log "Failed to get domain from config"
        return 1
    fi

    if [[ "${acme_legacy}" == "1" ]]; then
        if [[ ! -x "${acme_sh_dir}/acme.sh" ]]; then
            ssl_log "acme.sh not found at ${acme_sh_dir}"
            return 1
        fi
    else
        idleleo_bin=$(command -v idleleo 2>/dev/null || true)
        if [[ -z "${idleleo_bin}" ]]; then
            ssl_log "idleleo not found on PATH"
            return 1
        fi
        if [[ ! -d "${idleleo_dir}/conf" ]]; then
            ssl_log "ACME webroot not found: ${idleleo_dir}/conf"
            return 1
        fi
    fi

    if ! mkdir -p "${ssl_chainpath}" 2>/dev/null || [[ ! -d "${ssl_chainpath}" ]]; then
        ssl_log "Certificate directory is not usable: ${ssl_chainpath}"
        return 1
    fi

    if command -v getent >/dev/null 2>&1 &&
        ! getent group "${cert_group}" >/dev/null 2>&1; then
        ssl_log "Required certificate group not found: ${cert_group}"
        return 1
    fi

    return 0
}

stop_nginx_for_renewal() {
    nginx_stopped="no"
    [[ -f "${nginx_systemd_file}" ]] || return 0
    systemctl is-active --quiet nginx >/dev/null 2>&1 || return 0
    if ! systemctl stop nginx >/dev/null 2>&1; then
        ssl_log "Warning: failed to stop Nginx before certificate renewal; continuing"
        return 0
    fi
    nginx_stopped="yes"
    return 0
}

restore_nginx_state() {
    [[ "${nginx_stopped}" == "yes" ]] || return 0
    if ! systemctl start nginx >/dev/null 2>&1; then
        return 1
    fi
    if ! systemctl is-active --quiet nginx >/dev/null 2>&1; then
        return 1
    fi
    nginx_stopped="no"
    return 0
}

renew_and_install_cert() {
    if [[ "${acme_legacy}" == "1" ]]; then
        if ! "${acme_sh_dir}/acme.sh" --cron --home "${acme_sh_dir}" >/dev/null 2>&1; then
            ssl_log "acme.sh cron renewal failed"
            return 1
        fi
        if ! "${acme_sh_dir}/acme.sh" --installcert -d "${host}" \
            --fullchainpath "${ssl_chainpath}/xray.crt" \
            --keypath "${ssl_chainpath}/xray.key" --ecc >/dev/null 2>&1; then
            ssl_log "acme.sh installcert failed for ${host}"
            return 1
        fi
    elif ! "${idleleo_bin}" xray cert renew \
        --domain "${host}" \
        --webroot "${idleleo_dir}/conf" \
        --cert-out "${ssl_chainpath}/xray.crt" \
        --key-out "${ssl_chainpath}/xray.key" \
        "${acme_dir_args[@]}"; then
        ssl_log "idleleo xray cert renew failed for ${host}"
        return 1
    fi

    if [[ ! -f "${ssl_chainpath}/xray.crt" || ! -f "${ssl_chainpath}/xray.key" ]]; then
        ssl_log "Certificate files missing after renewal"
        return 1
    fi

    return 0
}

apply_cert_permissions() {
    # Root owns certs/keys, worker group can read but NOT write.
    # Use non-recursive chown to avoid affecting other files in the directory.
    # Apply layered permission model consistent with apply_nginx_layered_permissions()
    # in install.sh: cert dir root:idleleo-nginx 750, cert/privkey root:idleleo-nginx 640.
    if ! chown -f "root:${cert_group}" "${ssl_chainpath}" ||
        ! chown -f "root:${cert_group}" "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key" ||
        ! chmod -f 750 "${ssl_chainpath}" ||
        ! chmod -f 640 "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key"; then
        ssl_log "Failed to apply layered certificate permissions"
        return 1
    fi
    return 0
}

# One restart per unit, driven by the state observed at the start of this run.
restart_services_after_renewal() {
    local rc=0
    if [[ -f "${xray_systemd_file}" ]] && systemctl is-active --quiet xray >/dev/null 2>&1; then
        if ! systemctl restart xray >/dev/null 2>&1; then
            ssl_log "Xray restart failed after SSL update"
            rc=1
        fi
    fi
    if [[ "${nginx_stopped}" == "yes" ]]; then
        if ! systemctl start nginx >/dev/null 2>&1 ||
            ! systemctl is-active --quiet nginx >/dev/null 2>&1; then
            ssl_log "Nginx start failed after SSL update"
            rc=1
        else
            nginx_stopped="no"
        fi
    fi
    return "${rc}"
}

ssl_update_main() {
    local rc=0

    if ! acquire_locks; then
        release_locks
        return 1
    fi

    preflight_checks || rc=1
    if [[ ${rc} -eq 0 ]]; then
        # HTTP-01 native issuance reads the token from the Nginx webroot, so
        # Nginx must stay up; only the legacy acme.sh path stops it.
        if [[ "${acme_legacy}" == "1" ]]; then
            stop_nginx_for_renewal
        fi
        renew_and_install_cert || rc=1
    fi
    if [[ ${rc} -eq 0 ]]; then
        apply_cert_permissions || rc=1
    fi
    if [[ ${rc} -eq 0 ]]; then
        restart_services_after_renewal || rc=1
    fi

    # Single recovery point for every failure branch: a unit that was running
    # before this run must be running again, and a unit that was stopped before
    # this run is never started.
    if [[ "${nginx_stopped}" == "yes" ]]; then
        if restore_nginx_state; then
            ssl_log "Nginx was running before the update and has been restored."
        else
            ssl_log "ERROR: Nginx was running before the update but could not be restarted; run 'systemctl start nginx' manually."
            rc=2
        fi
    fi

    release_locks
    return "${rc}"
}

_ssl_update_exit_trap() {
    local rc=$?
    if [[ "${nginx_stopped}" == "yes" ]]; then
        restore_nginx_state ||
            ssl_log "ERROR: Nginx was running before the update but could not be restarted; run 'systemctl start nginx' manually."
    fi
    release_locks
    return "${rc}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap '_ssl_update_exit_trap' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    ssl_update_main
    exit $?
fi
