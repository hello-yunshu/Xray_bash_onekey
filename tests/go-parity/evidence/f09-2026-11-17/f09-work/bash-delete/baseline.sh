set -euo pipefail
OK=; GreenBG=; Font=; Green=; Error=; RedBG=; Warning=; YellowBG=; Red=
log_echo(){ :; }
gettext(){ printf '%s' "$1"; }
fm_display_width(){ printf '%s' "${#1}"; }
fm_restart_nginx_and_check_status(){ :; }
fm_list_files(){ if [ "${1:-}" = true ]; then files=("127.0.0.1.${fm_EXTENSION}"); fi; }
pkg_install(){ :; }
ID=ubuntu
QUEUE=(1)
read_optimize(){ local _p="$1" _v="$2" _d="${3:-}"; local _n="${QUEUE[0]}"; QUEUE=("${QUEUE[@]:1}"); [ -z "$_n" ] && _n="$_d"; printf -v "$_v" '%s' "$_n"; }
fm_EXTENSION=realityServers
fm_delete_file() {
    if ! fm_list_files true; then
        return
    fi

    local num_files=${#files[@]}
    local choice
    read_optimize "$(gettext "请输入要删除的文件编号") (1-$num_files): " choice "" 1 "$num_files"

    local filename="${files[$((choice - 1))]}"

    rm "$filename"
    log_echo "${OK} ${GreenBG} $(gettext "文件") $filename $(gettext "已删除") ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}
fm_delete_file
