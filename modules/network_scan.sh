#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: Network Scanner
# Discovers hosts, enumerates services, identifies OT devices
# ═══════════════════════════════════════════════════════════════

run_network_scan() {
    local target="${1:?Usage: run_network_scan <target>}"
    log INFO "Network Scan — Target: $target"

    # ── Host Discovery ────────────────────────────────────────
    echo -e "  ${CYAN}[1/5]${NC} Host Discovery (ARP + ICMP)"
    if command -v nmap &>/dev/null; then
        if [[ $DRY_RUN -eq 1 ]]; then
            log DEBUG "DRY: nmap -sn $target"
        else
            local hosts
            hosts=$(nmap -sn "$target" 2>/dev/null | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()')
            local host_count
            host_count=$(echo "$hosts" | grep -c . || echo 0)
            log INFO "Discovered $host_count live host(s)"
            echo "$hosts" | while read -r h; do
                [[ -n "$h" ]] && log INFO "  ├─ Host: $h"
            done
        fi
    else
        log WARN "nmap not found — falling back to ping sweep"
        ping_sweep "$target"
    fi

    # ── OT-Specific Port Scan ─────────────────────────────────
    echo -e "  ${CYAN}[2/5]${NC} OT/ICS Port Scan"
    local ot_ports="20000,44818,102,502,1089-1091,2222,2404,4000,4840,4843,4911,9600,18245,34962-34964,34980,47808,55000,55001,55002,55003"
    if command -v nmap &>/dev/null; then
        if [[ $DRY_RUN -eq 1 ]]; then
            log DEBUG "DRY: nmap -sS -sV -p $ot_ports $target"
        else
            log INFO "Scanning OT-specific ports..."
            nmap -sS -sV -p "$ot_ports" --open "$target" -oN "${REPORT_DIR}/ot_ports.txt" 2>/dev/null | \
                grep "open" | while read -r line; do
                    log INFO "  ├─ $line"
                done
        fi
    else
        manual_port_scan "$target" "$ot_ports"
    fi

    # ── Common Service Ports ──────────────────────────────────
    echo -e "  ${CYAN}[3/5]${NC} Common Service Ports"
    local common_ports="21,22,23,25,53,80,110,111,135,139,161,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"
    if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
        nmap -sS -p "$common_ports" --open "$target" -oN "${REPORT_DIR}/common_ports.txt" 2>/dev/null | \
            grep "open" | while read -r line; do
                log INFO "  ├─ $line"
            done
    fi

    # ── MAC Address / Vendor Lookup ───────────────────────────
    echo -e "  ${CYAN}[4/5]${NC} MAC Address / OT Vendor Identification"
    identify_ot_vendors "$target"

    # ── Banner Grabbing ───────────────────────────────────────
    echo -e "  ${CYAN}[5/5]${NC} Service Banner Grabbing"
    banner_grab "$target"

    log INFO "Network scan module completed."
}

ping_sweep() {
    local target="$1"
    if [[ "$target" == *"/"* ]]; then
        local base prefix
        base=$(echo "$target" | cut -d'/' -f1)
        prefix=$(echo "$target" | cut -d'/' -f2)
        local network
        network=$(echo "$base" | cut -d'.' -f1-3)
        for i in $(seq 1 254); do
            (ping -c 1 -W 1 "${network}.${i}" &>/dev/null && \
                log INFO "  ├─ Host alive: ${network}.${i}") &
            [[ $((i % THREADS)) -eq 0 ]] && wait
        done
        wait
    else
        ping -c 3 "$target" &>/dev/null && log INFO "Host $target is alive" || log WARN "Host $target is not responding to ICMP"
    fi
}

manual_port_scan() {
    local target="$1" ports="$2"
    log INFO "Fallback: TCP connect scan on key ports"
    IFS=',' read -ra PORT_LIST <<< "$ports"
    for port in "${PORT_LIST[@]}"; do
        if [[ "$port" == *"-"* ]]; then
            local start end
            start=$(echo "$port" | cut -d'-' -f1)
            end=$(echo "$port" | cut -d'-' -f2)
            for p in $(seq "$start" "$end"); do
                (echo >/dev/tcp/"$target"/"$p" 2>/dev/null && \
                    log INFO "  ├─ Port $p/tcp OPEN") &
            done
        else
            (echo >/dev/tcp/"$target"/"$port" 2>/dev/null && \
                log INFO "  ├─ Port $port/tcp OPEN") &
        fi
    done
    wait
}

identify_ot_vendors() {
    local target="$1"
    local ot_oui_patterns=(
        "00:00:BC|Rockwell"
        "00:01:05|Beckhoff"
        "00:0E:8C|Siemens"
        "00:0F:23|Schneider"
        "00:20:4A|Prosoft"
        "00:30:11|HMS"
        "00:40:9D|ABB"
        "00:60:35|Dallas/Maxim"
        "00:80:F4|Telemecanique"
        "00:A0:45|Phoenix Contact"
        "00:C0:C7|WAGO"
        "00:D0:C9|Advantech"
        "08:00:06|Honeywell"
        "28:63:36|Siemens"
        "5C:88:16|Emerson"
        "64:00:F1|Cisco_Industrial"
        "B4:8A:0A|GE_Intelligent"
    )

    if command -v arp &>/dev/null; then
        local arp_output
        arp_output=$(arp -an 2>/dev/null || true)
        for pattern in "${ot_oui_patterns[@]}"; do
            local oui vendor
            oui=$(echo "$pattern" | cut -d'|' -f1)
            vendor=$(echo "$pattern" | cut -d'|' -f2)
            if echo "$arp_output" | grep -qi "$oui"; then
                log WARN "OT Vendor detected: ${BOLD}${vendor}${NC} (OUI: $oui)"
            fi
        done
    fi
}

banner_grab() {
    local target="$1"
    local grab_ports=(21 22 23 80 102 443 502 4840 8080 44818 47808)
    for port in "${grab_ports[@]}"; do
        local banner
        banner=$(timeout 3 bash -c "echo '' | nc -w 2 $target $port 2>/dev/null" | head -1 || true)
        if [[ -n "$banner" ]]; then
            log INFO "  ├─ Port $port banner: ${banner:0:80}"
        fi
    done
}
