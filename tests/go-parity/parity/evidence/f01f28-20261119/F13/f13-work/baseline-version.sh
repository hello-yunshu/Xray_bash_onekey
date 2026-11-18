set -uo pipefail
version_is_numeric() {
    [[ "${1:-}" =~ ^[0-9]+(\.[0-9]+)*$ ]]
}
version_compare() {
    local a="${1#v}" b="${2#v}"
    local i n x y
    local -a av bv
    version_is_numeric "${a}" && version_is_numeric "${b}" || return 2
    IFS='.' read -r -a av <<<"${a}"
    IFS='.' read -r -a bv <<<"${b}"
    n=${#av[@]}
    [[ ${#bv[@]} -gt ${n} ]] && n=${#bv[@]}
    for ((i = 0; i < n; i++)); do
        x=$((10#${av[i]:-0}))
        y=$((10#${bv[i]:-0}))
        if [[ ${x} -gt ${y} ]]; then
            printf '1\n'
            return 0
        fi
        if [[ ${x} -lt ${y} ]]; then
            printf -- '-1\n'
            return 0
        fi
    done
    printf '0\n'
}
version_gt() {
    [[ "$(version_compare "$1" "$2")" == "1" ]]
}
pairs=(
"1.8.24|1.8.20"
"1.8.20|1.8.24"
"1.8.20|1.8.20"
"1.8|1.8.0"
"26.9.30|26.10.31"
"2026.10.15.7679|2026.10.15.2"
"1.10|1.9"
"2.0|1.99.99"
"1.0.0.1|1.0.0"
)
for pair in "${pairs[@]}"; do
    a=${pair%%|*}
    b=${pair##*|}
    printf '%s|%s|%s\n' "$a" "$b" "$(version_compare "$a" "$b")"
done
