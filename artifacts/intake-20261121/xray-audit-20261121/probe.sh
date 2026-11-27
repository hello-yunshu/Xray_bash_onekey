# Transcribed from install.sh:9219-9222, 0fa7052e.
format_xhttp_path() {
    local raw_path="$1"
    echo "/${raw_path#/}"
}
format_xhttp_path "$1"
