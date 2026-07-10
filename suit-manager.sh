#!/usr/bin/env bash
#
# suit-manager.sh - Interactive management tool for the "suit" tunneling binary
# Manager v2.1.0
#
set -Eeuo pipefail

# ============================================================================
# Global constants / configurable variables
# ============================================================================

readonly MANAGER_VERSION="Manager v2.1.0"
GITHUB_REPO="OWNER/REPO"   # <-- change to actual owner/repo, e.g. "myorg/suit"

readonly SUIT_BIN="/opt/suit/suit"
readonly SUIT_WORKDIR="/opt/suit"
readonly SUIT_CONFDIR="/etc/suit"
readonly SUIT_LOGDIR="/var/log/suit"
readonly SYSTEMD_TEMPLATE="/etc/systemd/system/suit@.service"
readonly SYSTEMD_UNIT_PREFIX="suit@"

# ============================================================================
# Colors / UI helpers
# ============================================================================

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_MAGENTA=$'\033[35m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
    C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi

info()    { printf '%s[INFO]%s %s\n'  "${C_CYAN}"   "${C_RESET}" "$*"; }
ok()      { printf '%s[ OK ]%s %s\n'  "${C_GREEN}"  "${C_RESET}" "$*"; }
warn()    { printf '%s[WARN]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
err()     { printf '%s[FAIL]%s %s\n' "${C_RED}"    "${C_RESET}" "$*" >&2; }
title()   { printf '\n%s%s==== %s ====%s\n' "${C_BOLD}" "${C_MAGENTA}" "$*" "${C_RESET}"; }
section() { printf '\n%s%s--- %s ---%s\n' "${C_BOLD}" "${C_BLUE}" "$*" "${C_RESET}"; }

print_header() {
    printf '%s' "${C_CYAN}"
    cat <<'EOF'
  ____        _ _     __  __
 / ___| _   _(_) |_  |  \/  | __ _ _ __   __ _  __ _  ___ _ __
 \___ \| | | | | __| | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
  ___) | |_| | | |_  | |  | | (_| | | | | (_| | (_| |  __/ |
 |____/ \__,_|_|\__| |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|
                                                |___/
EOF
    printf '%s' "${C_RESET}"
    printf '%sSuit Tunnel Manager - %s%s\n' "${C_DIM}" "${MANAGER_VERSION}" "${C_RESET}"
}

# ============================================================================
# Error trapping
# ============================================================================

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    err "Unexpected error (exit code ${exit_code}) at line ${line_no}."
    exit "${exit_code}"
}
trap 'on_error ${LINENO}' ERR

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        err "This script must be run as root. Try: sudo bash $0 $*"
        exit 1
    fi
}

# ============================================================================
# Dependency checks
# ============================================================================

check_dependencies() {
    local missing=()
    for cmd in systemctl journalctl ip awk sed grep; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing+=("curl-or-wget")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required dependencies: ${missing[*]}"
        err "Please install them and re-run this script."
        exit 1
    fi
}

# ============================================================================
# Generic input helpers
# ============================================================================

# ask_yes_no "Prompt" default(y|n) -> echoes "yes" or "no"
ask_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    local hint="y/N"
    [[ "$default" == "y" ]] && hint="Y/n"
    local reply
    while true; do
        read -r -p "$(printf '%s%s%s [%s]: ' "${C_YELLOW}" "$prompt" "${C_RESET}" "$hint")" reply || true
        reply="${reply:-$default}"
        case "${reply,,}" in
            y|yes) echo "yes"; return 0 ;;
            n|no)  echo "no";  return 0 ;;
            *) warn "Please answer yes or no." ;;
        esac
    done
}

# ask_menu "Title" default_index "opt1" "opt2" ... -> echoes chosen option string
ask_menu() {
    local prompt="$1"; shift
    local default_idx="$1"; shift
    local -a options=("$@")
    local i
    printf '%s%s%s\n' "${C_YELLOW}" "$prompt" "${C_RESET}"
    for i in "${!options[@]}"; do
        printf '  %d) %s\n' "$((i+1))" "${options[$i]}"
    done
    local choice
    while true; do
        read -r -p "Select [1-${#options[@]}] (default ${default_idx}): " choice || true
        choice="${choice:-$default_idx}"
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            echo "${options[$((choice-1))]}"
            return 0
        fi
        warn "Invalid choice, try again."
    done
}

# ask_string "Prompt" "default" -> echoes value (allows empty if default empty and user confirms)
ask_string() {
    local prompt="$1"
    local default="${2:-}"
    local value
    if [[ -n "$default" ]]; then
        read -r -p "$(printf '%s%s%s [%s]: ' "${C_YELLOW}" "$prompt" "${C_RESET}" "$default")" value || true
        value="${value:-$default}"
    else
        read -r -p "$(printf '%s%s%s: ' "${C_YELLOW}" "$prompt" "${C_RESET}")" value || true
    fi
    echo "$value"
}

# ============================================================================
# Validators
# ============================================================================

is_valid_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    local o
    for o in "${octets[@]}"; do
        [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1
        (( o >= 0 && o <= 255 )) || return 1
        # reject leading zero like "01"
        [[ "$o" != "0" && "$o" =~ ^0 ]] && return 1
    done
    return 0
}

is_valid_ipv4_list() {
    local list="$1"
    [[ -z "$list" ]] && return 0
    local IFS=','
    local -a items
    read -ra items <<< "$list"
    local item trimmed
    for item in "${items[@]}"; do
        trimmed="$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        is_valid_ipv4 "$trimmed" || return 1
    done
    return 0
}

is_valid_netmask() {
    local mask="$1"
    is_valid_ipv4 "$mask" || return 1
    # Convert to binary and ensure contiguous 1s followed by 0s
    local IFS='.'
    local -a o
    read -ra o <<< "$mask"
    local bin=""
    local part
    for part in "${o[@]}"; do
        bin+=$(printf '%08d' "$(bc <<< "obase=2; $part" 2>/dev/null || echo 0)")
    done
    # Fallback simpler check using awk if bc unavailable
    if [[ -z "$bin" || "$bin" == *"00000000"* && "$bin" != *"1"* ]]; then
        : # keep going, fallback below
    fi
    # Simple python-free contiguous-ones check via awk
    local valid
    valid=$(awk -v ip="$mask" '
        BEGIN {
            split(ip, o, ".")
            bin = ""
            for (i = 1; i <= 4; i++) {
                v = o[i] + 0
                b = ""
                for (j = 7; j >= 0; j--) {
                    b = b (int(v / (2^j)) % 2)
                }
                bin = bin b
            }
            seenZero = 0
            ok = 1
            for (i = 1; i <= length(bin); i++) {
                c = substr(bin, i, 1)
                if (c == "0") seenZero = 1
                if (c == "1" && seenZero == 1) { ok = 0 }
            }
            print ok
        }')
    [[ "$valid" == "1" ]] || return 1
    return 0
}

is_valid_int_range() {
    local val="$1" min="$2" max="$3"
    [[ "$val" =~ ^[0-9]+$ ]] || return 1
    (( val >= min && val <= max )) || return 1
    return 0
}

is_valid_port_list() {
    local list="$1"
    [[ -z "$list" ]] && return 0
    local IFS=','
    local -a items
    read -ra items <<< "$list"
    local item trimmed
    for item in "${items[@]}"; do
        trimmed="$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        is_valid_int_range "$trimmed" 1 65535 || return 1
    done
    return 0
}

sanitize_instance_name() {
    local name="$1"
    echo "$name" | tr -cd 'A-Za-z0-9_-'
}

is_valid_instance_name() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || return 1
    return 0
}

is_valid_nic_name() {
    local nic="$1"
    [[ "$nic" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    if command -v ip >/dev/null 2>&1; then
        if ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -qx "$nic"; then
            return 0
        else
            return 1
        fi
    fi
    return 0
}

detect_default_nic() {
    local nic
    nic="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -z "$nic" ]]; then
        nic="eth0"
    fi
    echo "$nic"
}

generate_random_hex() {
    local bytes="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$bytes"
    elif [[ -r /dev/urandom ]]; then
        od -An -tx1 -N "$bytes" /dev/urandom | tr -d ' \n'
    else
        date +%s%N | sha256sum | head -c $((bytes * 2))
    fi
}

# ============================================================================
# Binary installation
# ============================================================================

get_installed_version() {
    if [[ -x "$SUIT_BIN" ]]; then
        "$SUIT_BIN" --version 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

http_get() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url"
    else
        wget -qO- "$url"
    fi
}

download_file() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --progress-bar -o "$out" "$url"
    else
        wget -q --show-progress -O "$out" "$url"
    fi
}

# Parse GitHub latest release JSON to find a suitable asset download URL.
find_release_asset_url() {
    local json="$1"
    local url=""

    if command -v python3 >/dev/null 2>&1; then
        url="$(python3 - "$json" <<'PYEOF' 2>/dev/null || true
import json, re, sys
data = sys.argv[1]
try:
    obj = json.loads(data)
except Exception:
    sys.exit(0)
assets = obj.get("assets", [])
pattern = re.compile(r'(?i)suit.*(linux).*(x86_64|amd64)')
best = None
for a in assets:
    name = a.get("name", "")
    if pattern.search(name):
        best = a.get("browser_download_url")
        break
if best:
    print(best)
PYEOF
)"
    fi

    if [[ -z "$url" ]]; then
        # Bash/grep fallback parser
        url="$(echo "$json" \
            | grep -Eo '"browser_download_url":[[:space:]]*"[^"]*(linux)[^"]*(x86_64|amd64)[^"]*"' \
            | head -n1 \
            | sed -E 's/.*"([^"]+)"$/\1/')"
    fi

    echo "$url"
}

install_binary() {
    section "Binary Installation"

    local current_version
    current_version="$(get_installed_version)"
    info "Currently installed version: ${current_version}"

    if [[ -x "$SUIT_BIN" ]]; then
        local redl
        redl="$(ask_yes_no "Binary already exists. Re-download latest release?" n)"
        [[ "$redl" == "no" ]] && { ok "Keeping existing binary."; return 0; }
    fi

    if [[ "$GITHUB_REPO" == "OWNER/REPO" ]]; then
        err "GITHUB_REPO is not configured. Edit the script and set GITHUB_REPO=\"owner/repo\"."
        return 1
    fi

    info "Querying latest release for ${GITHUB_REPO} ..."
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local json
    if ! json="$(http_get "$api_url")"; then
        err "Failed to query GitHub API at ${api_url}"
        return 1
    fi

    local asset_url
    asset_url="$(find_release_asset_url "$json")"

    if [[ -z "$asset_url" ]]; then
        err "Could not find a suitable linux amd64/x86_64 asset in the latest release."
        return 1
    fi

    info "Found asset: ${asset_url}"
    mkdir -p "$SUIT_WORKDIR"
    local tmp_file
    tmp_file="$(mktemp)"

    info "Downloading binary..."
    if ! download_file "$asset_url" "$tmp_file"; then
        err "Download failed."
        rm -f "$tmp_file"
        return 1
    fi

    mv "$tmp_file" "$SUIT_BIN"
    chmod 755 "$SUIT_BIN"
    ok "Binary installed to ${SUIT_BIN}"

    local new_version
    new_version="$(get_installed_version)"
    info "Installed version: ${new_version}"
}

# ============================================================================
# TOML config generation
# ============================================================================

# Convert comma list into TOML array of quoted strings
toml_string_array() {
    local list="$1"
    if [[ -z "$list" ]]; then
        echo "[]"
        return 0
    fi
    local IFS=','
    local -a items
    read -ra items <<< "$list"
    local out="["
    local first=1
    local item trimmed
    for item in "${items[@]}"; do
        trimmed="$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$trimmed" ]] && continue
        if [[ $first -eq 1 ]]; then
            out+="\"${trimmed}\""
            first=0
        else
            out+=", \"${trimmed}\""
        fi
    done
    out+="]"
    echo "$out"
}

# Convert comma list of integers into TOML array of numbers
toml_int_array() {
    local list="$1"
    if [[ -z "$list" ]]; then
        echo "[]"
        return 0
    fi
    local IFS=','
    local -a items
    read -ra items <<< "$list"
    local out="["
    local first=1
    local item trimmed
    for item in "${items[@]}"; do
        trimmed="$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$trimmed" ]] && continue
        if [[ $first -eq 1 ]]; then
            out+="${trimmed}"
            first=0
        else
            out+=", ${trimmed}"
        fi
    done
    out+="]"
    echo "$out"
}

# ============================================================================
# Configuration wizard
# ============================================================================

run_configuration_wizard() {
    require_root
    mkdir -p "$SUIT_CONFDIR" "$SUIT_WORKDIR" "$SUIT_LOGDIR"

    title "Suit Instance Configuration Wizard"
    printf '%sEvery option is configurable. Press Enter to accept the default shown in [brackets].%s\n' "${C_DIM}" "${C_RESET}"

    # ---- Instance name ----
    local instance
    while true; do
        instance="$(ask_string "Instance name" "suit0")"
        instance="$(sanitize_instance_name "$instance")"
        if ! is_valid_instance_name "$instance"; then
            warn "Invalid instance name. Use only alphanumeric, '_' and '-'."
            continue
        fi
        local cfg_path="${SUIT_CONFDIR}/${instance}.toml"
        if [[ -f "$cfg_path" ]]; then
            local overwrite
            overwrite="$(ask_yes_no "Config for '${instance}' already exists. Overwrite?" n)"
            [[ "$overwrite" == "no" ]] && continue
        fi
        break
    done
    local cfg_path="${SUIT_CONFDIR}/${instance}.toml"

    # ---- 1. Role ----
    section "1. Role"
    local role
    role="$(ask_menu "Select instance role:" 1 "client" "server")"
    ok "Role: ${role}"

    # ---- 2. Spoofing Mode ----
    section "2. Spoofing Mode"
    info "Spoofing lets the tunnel present traffic with a different (spoofed)"
    info "source IP than the real one, useful for certain routing/bypass setups."
    local enable_spoofing
    enable_spoofing="$(ask_yes_no "Enable IP spoofing?" y)"

    # ---- 3. IP Addressing ----
    section "3. IP Addressing"
    local local_real_ip peer_real_ip spoofed_ip spoofed_ip_pool peer_spoofed_ip allowed_peers

    while true; do
        local_real_ip="$(ask_string "Local real IP (e.g. your server's public/real IP)" "")"
        is_valid_ipv4 "$local_real_ip" && break
        warn "Invalid IPv4 address."
    done

    while true; do
        peer_real_ip="$(ask_string "Peer real IP (the other side's real IP)" "")"
        is_valid_ipv4 "$peer_real_ip" && break
        warn "Invalid IPv4 address."
    done

    if [[ "$enable_spoofing" == "yes" ]]; then
        while true; do
            spoofed_ip="$(ask_string "Spoofed IP (source IP to present)" "")"
            is_valid_ipv4 "$spoofed_ip" && break
            warn "Invalid IPv4 address."
        done
        spoofed_ip_pool="$(ask_string "Spoofed IP pool (comma-separated IPv4 list, optional)" "")"
        while ! is_valid_ipv4_list "$spoofed_ip_pool"; do
            warn "Invalid IPv4 list."
            spoofed_ip_pool="$(ask_string "Spoofed IP pool (comma-separated IPv4 list, optional)" "")"
        done
        while true; do
            peer_spoofed_ip="$(ask_string "Peer spoofed IP" "")"
            is_valid_ipv4 "$peer_spoofed_ip" && break
            warn "Invalid IPv4 address."
        done
    else
        spoofed_ip=""
        spoofed_ip_pool=""
        peer_spoofed_ip=""
    fi

    allowed_peers="$(ask_string "Allowed peers (comma-separated IPv4 list, or 'none')" "none")"
    [[ "${allowed_peers,,}" == "none" ]] && allowed_peers=""
    while ! is_valid_ipv4_list "$allowed_peers"; do
        warn "Invalid IPv4 list."
        allowed_peers="$(ask_string "Allowed peers (comma-separated IPv4 list, or 'none')" "none")"
        [[ "${allowed_peers,,}" == "none" ]] && allowed_peers=""
    done

    # ---- 4. Transport Protocol ----
    section "4. Transport Protocol"
    local uplink_protocol downlink_protocol data_port shuffle_data_port
    uplink_protocol="$(ask_menu "Uplink protocol:" 1 udp icmp proto58 tcp quic ipip gre)"
    downlink_protocol="$(ask_menu "Downlink protocol:" 1 udp icmp proto58 tcp quic ipip gre)"

    while true; do
        data_port="$(ask_string "Data port" "443")"
        is_valid_int_range "$data_port" 1 65535 && break
        warn "Port must be an integer between 1 and 65535."
    done

    shuffle_data_port="$(ask_yes_no "Shuffle data port?" n)"

    # ---- 5. Multiplexing & FEC ----
    section "5. Multiplexing & FEC"
    local enable_mux mux_flush_ms mux_max_payload enable_fec

    local is_tcp_or_quic="no"
    if [[ "$uplink_protocol" == "tcp" || "$uplink_protocol" == "quic" || \
          "$downlink_protocol" == "tcp" || "$downlink_protocol" == "quic" ]]; then
        is_tcp_or_quic="yes"
    fi

    enable_mux="$(ask_yes_no "Enable multiplexing?" y)"

    if [[ "$enable_mux" == "yes" ]]; then
        while true; do
            mux_flush_ms="$(ask_string "Mux flush interval (ms)" "1")"
            is_valid_int_range "$mux_flush_ms" 0 100000 && break
            warn "Must be a non-negative integer."
        done
        while true; do
            mux_max_payload="$(ask_string "Mux max payload (bytes)" "1380")"
            is_valid_int_range "$mux_max_payload" 1 65535 && break
            warn "Must be an integer between 1 and 65535."
        done
    else
        mux_flush_ms=1
        mux_max_payload=1380
    fi

    enable_fec="$(ask_yes_no "Enable FEC (forward error correction)?" n)"
    if [[ "$enable_fec" == "yes" && "$is_tcp_or_quic" == "yes" ]]; then
        warn "FEC is not compatible with TCP/QUIC transport. Disabling FEC."
        enable_fec="no"
    fi

    # ---- 6. Security ----
    section "6. Security"
    local pre_shared_key enable_xor xor_key

    pre_shared_key="$(ask_string "Pre-shared key (leave empty to auto-generate)" "")"
    if [[ -z "$pre_shared_key" ]]; then
        pre_shared_key="$(generate_random_hex 32)"
        info "Generated pre-shared key: ${pre_shared_key}"
    fi

    enable_xor="$(ask_yes_no "Enable XOR obfuscation layer?" y)"
    if [[ "$enable_xor" == "yes" ]]; then
        xor_key="$(ask_string "XOR key (empty = derive from pre-shared key)" "")"
    else
        xor_key=""
    fi

    # ---- 7. DPI Bypass Obfuscation ----
    section "7. DPI Bypass Obfuscation"
    local enable_padding padding_max_bytes enable_ttl_jitter fake_tls_header random_dscp

    enable_padding="$(ask_yes_no "Enable packet padding?" y)"
    if [[ "$enable_padding" == "yes" ]]; then
        while true; do
            padding_max_bytes="$(ask_string "Padding max bytes (1-255)" "64")"
            is_valid_int_range "$padding_max_bytes" 1 255 && break
            warn "Must be an integer between 1 and 255."
        done
    else
        padding_max_bytes=64
    fi

    enable_ttl_jitter="$(ask_yes_no "Enable TTL jitter?" y)"
    fake_tls_header="$(ask_yes_no "Enable fake TLS header?" n)"

    if [[ "$fake_tls_header" == "yes" && "$uplink_protocol" != "tcp" && "$downlink_protocol" != "tcp" ]]; then
        warn "Fake TLS header requires TCP transport. Disabling fake_tls_header."
        fake_tls_header="no"
    fi

    random_dscp="$(ask_yes_no "Enable random DSCP marking?" n)"

    # ---- 8. TUN Interface ----
    section "8. TUN Interface"
    local tun_name tun_ip tun_peer_ip tun_netmask nic_name mtu tun_mtu forward_ports
    local default_tun_ip default_tun_peer_ip

    if [[ "$role" == "client" ]]; then
        default_tun_ip="10.66.0.1"
        default_tun_peer_ip="10.66.0.2"
    else
        default_tun_ip="10.66.0.2"
        default_tun_peer_ip="10.66.0.1"
    fi

    tun_name="$(ask_string "TUN interface name" "$instance")"
    tun_name="$(sanitize_instance_name "$tun_name")"

    while true; do
        tun_ip="$(ask_string "TUN local IP" "$default_tun_ip")"
        is_valid_ipv4 "$tun_ip" && break
        warn "Invalid IPv4 address."
    done

    while true; do
        tun_peer_ip="$(ask_string "TUN peer IP" "$default_tun_peer_ip")"
        is_valid_ipv4 "$tun_peer_ip" && break
        warn "Invalid IPv4 address."
    done

    while true; do
        tun_netmask="$(ask_string "TUN netmask" "255.255.255.252")"
        is_valid_netmask "$tun_netmask" && break
        warn "Invalid netmask."
    done

    local detected_nic
    detected_nic="$(detect_default_nic)"
    while true; do
        nic_name="$(ask_string "Uplink NIC name (auto-detected)" "$detected_nic")"
        if is_valid_nic_name "$nic_name"; then
            break
        else
            warn "NIC '${nic_name}' not found on this system or invalid name. Please re-enter."
        fi
    done

    while true; do
        mtu="$(ask_string "MTU" "1380")"
        is_valid_int_range "$mtu" 500 9200 && break
        warn "MTU must be an integer between 500 and 9200."
    done

    while true; do
        tun_mtu="$(ask_string "TUN MTU" "$mtu")"
        is_valid_int_range "$tun_mtu" 500 9200 && break
        warn "TUN MTU must be an integer between 500 and 9200."
    done

    forward_ports="$(ask_string "Forward ports (comma-separated, empty = all)" "")"
    while ! is_valid_port_list "$forward_ports"; do
        warn "Invalid port list."
        forward_ports="$(ask_string "Forward ports (comma-separated, empty = all)" "")"
    done

    # ---- 9. Performance ----
    section "9. Performance"
    local performance_mode auto_tune
    performance_mode="$(ask_menu "Performance mode:" 1 throughput latency balanced)"
    auto_tune="$(ask_yes_no "Enable auto-tune?" y)"

    # ---- 10. Save + systemd ----
    section "10. Save Configuration"
    write_toml_config "$cfg_path" \
        "$role" "$enable_spoofing" \
        "$local_real_ip" "$peer_real_ip" "$spoofed_ip" "$spoofed_ip_pool" "$peer_spoofed_ip" "$allowed_peers" \
        "$uplink_protocol" "$downlink_protocol" "$data_port" "$shuffle_data_port" \
        "$enable_mux" "$mux_flush_ms" "$mux_max_payload" "$enable_fec" \
        "$pre_shared_key" "$enable_xor" "$xor_key" \
        "$enable_padding" "$padding_max_bytes" "$enable_ttl_jitter" "$fake_tls_header" "$random_dscp" \
        "$tun_name" "$tun_ip" "$tun_peer_ip" "$tun_netmask" "$nic_name" "$mtu" "$tun_mtu" "$forward_ports" \
        "$performance_mode" "$auto_tune"

    ok "Configuration saved to ${cfg_path}"

    ensure_systemd_template

    local do_enable do_start
    do_enable="$(ask_yes_no "Enable ${instance} to start on boot?" y)"
    if [[ "$do_enable" == "yes" ]]; then
        systemctl enable "${SYSTEMD_UNIT_PREFIX}${instance}.service" >/dev/null 2>&1 || true
        ok "Enabled ${instance} on boot."
    fi

    do_start="$(ask_yes_no "Start ${instance} now?" y)"
    if [[ "$do_start" == "yes" ]]; then
        systemctl restart "${SYSTEMD_UNIT_PREFIX}${instance}.service"
        ok "Started ${instance}."
    fi
}

write_toml_config() {
    local cfg_path="$1"; shift
    local role="$1" enable_spoofing="$2"
    local local_real_ip="$3" peer_real_ip="$4" spoofed_ip="$5" spoofed_ip_pool="$6" peer_spoofed_ip="$7" allowed_peers="$8"
    local uplink_protocol="$9" downlink_protocol="${10}" data_port="${11}" shuffle_data_port="${12}"
    local enable_mux="${13}" mux_flush_ms="${14}" mux_max_payload="${15}" enable_fec="${16}"
    local pre_shared_key="${17}" enable_xor="${18}" xor_key="${19}"
    local enable_padding="${20}" padding_max_bytes="${21}" enable_ttl_jitter="${22}" fake_tls_header="${23}" random_dscp="${24}"
    local tun_name="${25}" tun_ip="${26}" tun_peer_ip="${27}" tun_netmask="${28}" nic_name="${29}" mtu="${30}" tun_mtu="${31}" forward_ports="${32}"
    local performance_mode="${33}" auto_tune="${34}"

    local allowed_peers_arr forward_ports_arr spoofed_pool_arr
    allowed_peers_arr="$(toml_string_array "$allowed_peers")"
    forward_ports_arr="$(toml_int_array "$forward_ports")"
    spoofed_pool_arr="$(toml_string_array "$spoofed_ip_pool")"

    local tmp_cfg
    tmp_cfg="$(mktemp)"

    {
        echo "# Generated by suit-manager.sh (${MANAGER_VERSION})"
        echo "# Instance config"
        echo
        echo "[general]"
        echo "role = \"${role}\""
        echo "enable_spoofing = $([ "$enable_spoofing" = "yes" ] && echo true || echo false)"
        echo
        echo "[network]"
        echo "local_real_ip = \"${local_real_ip}\""
        echo "peer_real_ip = \"${peer_real_ip}\""
        echo "spoofed_ip = \"${spoofed_ip}\""
        echo "spoofed_ip_pool = ${spoofed_pool_arr}"
        echo "peer_spoofed_ip = \"${peer_spoofed_ip}\""
        echo "allowed_peers = ${allowed_peers_arr}"
        echo
        echo "[transport]"
        echo "uplink_protocol = \"${uplink_protocol}\""
        echo "downlink_protocol = \"${downlink_protocol}\""
        echo "data_port = ${data_port}"
        echo "shuffle_data_port = $([ "$shuffle_data_port" = "yes" ] && echo true || echo false)"
        echo
        echo "[mux_fec]"
        echo "enable_mux = $([ "$enable_mux" = "yes" ] && echo true || echo false)"
        echo "mux_flush_ms = ${mux_flush_ms}"
        echo "mux_max_payload = ${mux_max_payload}"
        echo "enable_fec = $([ "$enable_fec" = "yes" ] && echo true || echo false)"
        echo
        echo "[security]"
        echo "pre_shared_key = \"${pre_shared_key}\""
        echo "enable_xor = $([ "$enable_xor" = "yes" ] && echo true || echo false)"
        echo "xor_key = \"${xor_key}\""
        echo
        echo "[dpi_bypass]"
        echo "enable_padding = $([ "$enable_padding" = "yes" ] && echo true || echo false)"
        echo "padding_max_bytes = ${padding_max_bytes}"
        echo "enable_ttl_jitter = $([ "$enable_ttl_jitter" = "yes" ] && echo true || echo false)"
        echo "fake_tls_header = $([ "$fake_tls_header" = "yes" ] && echo true || echo false)"
        echo "random_dscp = $([ "$random_dscp" = "yes" ] && echo true || echo false)"
        echo
        echo "[tun]"
        echo "tun_name = \"${tun_name}\""
        echo "tun_ip = \"${tun_ip}\""
        echo "tun_peer_ip = \"${tun_peer_ip}\""
        echo "tun_netmask = \"${tun_netmask}\""
        echo "nic_name = \"${nic_name}\""
        echo "mtu = ${mtu}"
        echo "tun_mtu = ${tun_mtu}"
        echo "forward_ports = ${forward_ports_arr}"
        echo
        echo "[performance]"
        echo "performance_mode = \"${performance_mode}\""
        echo "auto_tune = $([ "$auto_tune" = "yes" ] && echo true || echo false)"
    } > "$tmp_cfg"

    install -m 0640 "$tmp_cfg" "$cfg_path"
    rm -f "$tmp_cfg"
}

# ============================================================================
# Systemd management
# ============================================================================

ensure_systemd_template() {
    local tmp_unit
    tmp_unit="$(mktemp)"
    cat > "$tmp_unit" <<EOF
[Unit]
Description=Suit tunnel instance %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${SUIT_WORKDIR}
ExecStart=${SUIT_BIN} -c ${SUIT_CONFDIR}/%i.toml
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=false
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    install -m 0644 "$tmp_unit" "$SYSTEMD_TEMPLATE"
    rm -f "$tmp_unit"
    systemctl daemon-reload
}

instance_config_path() {
    echo "${SUIT_CONFDIR}/$1.toml"
}

require_instance_config() {
    local instance="$1"
    local cfg
    cfg="$(instance_config_path "$instance")"
    if [[ ! -f "$cfg" ]]; then
        err "No configuration found for instance '${instance}' (${cfg})."
        return 1
    fi
    return 0
}

svc_start() {
    local instance="$1"
    require_instance_config "$instance" || return 1
    systemctl start "${SYSTEMD_UNIT_PREFIX}${instance}.service"
    ok "Started ${instance}."
}

svc_stop() {
    local instance="$1"
    systemctl stop "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || warn "Instance '${instance}' was not running."
    ok "Stopped ${instance} (if it was running)."
}

svc_restart() {
    local instance="$1"
    require_instance_config "$instance" || return 1
    systemctl restart "${SYSTEMD_UNIT_PREFIX}${instance}.service"
    ok "Restarted ${instance}."
}

svc_status() {
    local instance="$1"
    require_instance_config "$instance" || return 1
    systemctl status "${SYSTEMD_UNIT_PREFIX}${instance}.service" --no-pager || true
}

svc_enable() {
    local instance="$1"
    require_instance_config "$instance" || return 1
    systemctl enable "${SYSTEMD_UNIT_PREFIX}${instance}.service"
    ok "Enabled ${instance} on boot."
}

svc_disable() {
    local instance="$1"
    systemctl disable "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || true
    ok "Disabled ${instance} on boot."
}

svc_logs() {
    local instance="$1"
    require_instance_config "$instance" || return 1
    journalctl -u "${SYSTEMD_UNIT_PREFIX}${instance}" -e --no-pager
}

list_instances() {
    section "Configured Instances"
    if [[ ! -d "$SUIT_CONFDIR" ]] || ! compgen -G "${SUIT_CONFDIR}/*.toml" >/dev/null 2>&1; then
        warn "No instances configured yet."
        return 0
    fi
    printf '%-20s %-10s %-10s\n' "INSTANCE" "ACTIVE" "ENABLED"
    printf '%-20s %-10s %-10s\n' "--------" "------" "-------"
    local f instance active enabled
    for f in "${SUIT_CONFDIR}"/*.toml; do
        instance="$(basename "$f" .toml)"
        if systemctl is-active --quiet "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null; then
            active="${C_GREEN}active${C_RESET}"
        else
            active="${C_DIM}inactive${C_RESET}"
        fi
        if systemctl is-enabled --quiet "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null; then
            enabled="${C_GREEN}yes${C_RESET}"
        else
            enabled="${C_DIM}no${C_RESET}"
        fi
        printf '%-20s %-20b %-20b\n' "$instance" "$active" "$enabled"
    done
}

remove_instance() {
    local instance="$1"
    local cfg
    cfg="$(instance_config_path "$instance")"
    if [[ ! -f "$cfg" ]]; then
        err "No configuration found for instance '${instance}'."
        return 1
    fi

    local confirm
    confirm="$(ask_yes_no "Remove instance '${instance}'? This will stop/disable it and delete its config." n)"
    [[ "$confirm" == "no" ]] && { info "Aborted."; return 0; }

    systemctl stop "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || true
    systemctl disable "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || true
    rm -f "$cfg"
    ok "Removed instance '${instance}'."
}

uninstall_all() {
    title "Uninstall Suit Manager"
    warn "This will remove the suit binary, ALL configs, and the systemd template."
    printf 'Type %sDELETE ALL%s to confirm: ' "${C_RED}" "${C_RESET}"
    local phrase
    read -r phrase || true
    if [[ "$phrase" != "DELETE ALL" ]]; then
        info "Confirmation phrase mismatch. Aborting uninstall."
        return 0
    fi

    if compgen -G "${SUIT_CONFDIR}/*.toml" >/dev/null 2>&1; then
        local f instance
        for f in "${SUIT_CONFDIR}"/*.toml; do
            instance="$(basename "$f" .toml)"
            systemctl stop "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || true
            systemctl disable "${SYSTEMD_UNIT_PREFIX}${instance}.service" 2>/dev/null || true
        done
    fi

    rm -rf "$SUIT_CONFDIR"
    rm -rf "$SUIT_WORKDIR"
    rm -f "$SYSTEMD_TEMPLATE"
    systemctl daemon-reload

    ok "Suit has been fully uninstalled."
}

# ============================================================================
# Full setup flow
# ============================================================================

full_setup() {
    title "Full Setup"
    mkdir -p "$SUIT_WORKDIR" "$SUIT_CONFDIR" "$SUIT_LOGDIR"
    chmod 750 "$SUIT_CONFDIR" "$SUIT_LOGDIR"
    install_binary
    run_configuration_wizard
    ok "Full setup complete."
}

# ============================================================================
# Help / usage
# ============================================================================

show_help() {
    print_header
    cat <<EOF

Usage:
  sudo bash suit-manager.sh <command> [instance]

Commands:
  setup             Full setup: install binary + configure an instance
  install-binary    Install or update the suit binary from GitHub releases
  configure         Run the interactive configuration wizard
  start <inst>      Start an instance
  stop <inst>        Stop an instance
  restart <inst>    Restart an instance
  status <inst>     Show systemd status of an instance
  enable <inst>     Enable an instance on boot
  disable <inst>    Disable an instance on boot
  logs <inst>       Tail journal logs for an instance
  list              List all configured instances and their state
  remove <inst>     Remove an instance's config (with confirmation)
  uninstall         Remove everything: binary, configs, systemd template
  help, --help      Show this help message

Examples:
  sudo bash suit-manager.sh setup
  sudo bash suit-manager.sh configure
  sudo bash suit-manager.sh start suit0
  sudo bash suit-manager.sh logs suit0

If no command is given, an interactive menu is shown.
EOF
}

# ============================================================================
# Interactive menu
# ============================================================================

prompt_instance_name_existing() {
    local prompt="$1"
    local instance
    read -r -p "$(printf '%s%s%s: ' "${C_YELLOW}" "$prompt" "${C_RESET}")" instance || true
    echo "$(sanitize_instance_name "$instance")"
}

interactive_menu() {
    while true; do
        print_header
        cat <<EOF

 1) Full setup
 2) Install/update binary
 3) Configure instance
 4) Start instance
 5) Stop instance
 6) Restart instance
 7) Status
 8) Logs
 9) List instances
10) Remove instance
11) Uninstall all
12) Help
 0) Exit
EOF
        local choice
        read -r -p "Select an option [0-12]: " choice || true
        case "$choice" in
            1) full_setup ;;
            2) install_binary ;;
            3) run_configuration_wizard ;;
            4) svc_start "$(prompt_instance_name_existing "Instance name to start")" ;;
            5) svc_stop "$(prompt_instance_name_existing "Instance name to stop")" ;;
            6) svc_restart "$(prompt_instance_name_existing "Instance name to restart")" ;;
            7) svc_status "$(prompt_instance_name_existing "Instance name for status")" ;;
            8) svc_logs "$(prompt_instance_name_existing "Instance name for logs")" ;;
            9) list_instances ;;
            10) remove_instance "$(prompt_instance_name_existing "Instance name to remove")" ;;
            11) uninstall_all ;;
            12) show_help ;;
            0) info "Bye."; exit 0 ;;
            *) warn "Invalid selection." ;;
        esac
        printf '\nPress Enter to continue...'
        read -r || true
    done
}

# ============================================================================
# Command dispatch
# ============================================================================

main() {
    check_dependencies

    local cmd="${1:-}"
    local arg="${2:-}"

    case "$cmd" in
        "" )
            require_root
            interactive_menu
            ;;
        setup)
            require_root
            full_setup
            ;;
        install-binary)
            require_root
            install_binary
            ;;
        configure)
            require_root
            run_configuration_wizard
            ;;
        start)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 start <instance>"; exit 1; }
            svc_start "$(sanitize_instance_name "$arg")"
            ;;
        stop)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 stop <instance>"; exit 1; }
            svc_stop "$(sanitize_instance_name "$arg")"
            ;;
        restart)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 restart <instance>"; exit 1; }
            svc_restart "$(sanitize_instance_name "$arg")"
            ;;
        status)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 status <instance>"; exit 1; }
            svc_status "$(sanitize_instance_name "$arg")"
            ;;
        enable)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 enable <instance>"; exit 1; }
            svc_enable "$(sanitize_instance_name "$arg")"
            ;;
        disable)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 disable <instance>"; exit 1; }
            svc_disable "$(sanitize_instance_name "$arg")"
            ;;
        logs)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 logs <instance>"; exit 1; }
            svc_logs "$(sanitize_instance_name "$arg")"
            ;;
        list)
            require_root
            list_instances
            ;;
        remove)
            require_root
            [[ -z "$arg" ]] && { err "Usage: $0 remove <instance>"; exit 1; }
            remove_instance "$(sanitize_instance_name "$arg")"
            ;;
        uninstall)
            require_root
            uninstall_all
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            err "Unknown command: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
