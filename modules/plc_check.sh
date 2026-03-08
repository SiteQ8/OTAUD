#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: PLC / HMI / RTU Security Checker
# Identifies and assesses programmable logic controllers,
# human-machine interfaces, and remote terminal units
# ═══════════════════════════════════════════════════════════════

run_plc_check() {
    local target="${1:?Usage: run_plc_check <target>}"
    log INFO "PLC/HMI/RTU Security Check — Target: $target"

    identify_plc_type "$target"
    check_plc_access_control "$target"
    check_plc_firmware_mode "$target"
    check_hmi_exposure "$target"
    check_rtu_config "$target"
    check_program_upload "$target"

    log INFO "PLC/HMI/RTU security check completed."
}

# ── PLC Type Identification ──────────────────────────────────

identify_plc_type() {
    local target="$1"
    echo -e "  ${CYAN}[PLC ID]${NC} Identifying PLC type and model"

    # Siemens S7 (Port 102)
    if (echo >/dev/tcp/"$target"/102 2>/dev/null); then
        log INFO "  ├─ Siemens S7 PLC detected (port 102)"
        if command -v nmap &>/dev/null; then
            nmap -p 102 --script s7-info "$target" 2>/dev/null | grep -E "^\|" | while read -r line; do
                log INFO "  │  $line"
            done
        fi
    fi

    # Allen-Bradley/Rockwell (Port 44818)
    if (echo >/dev/tcp/"$target"/44818 2>/dev/null); then
        log INFO "  ├─ Allen-Bradley/Rockwell PLC detected (port 44818)"
        if command -v nmap &>/dev/null; then
            nmap -p 44818 --script enip-info "$target" 2>/dev/null | grep -E "^\|" | while read -r line; do
                log INFO "  │  $line"
            done
        fi
    fi

    # Modbus devices (Port 502)
    if (echo >/dev/tcp/"$target"/502 2>/dev/null); then
        log INFO "  ├─ Modbus device detected (port 502)"
    fi

    # Omron FINS (Port 9600)
    if (echo >/dev/tcp/"$target"/9600 2>/dev/null); then
        log INFO "  ├─ Omron PLC detected (FINS port 9600)"
    fi

    # Mitsubishi MELSEC (Port 5007)
    if (echo >/dev/tcp/"$target"/5007 2>/dev/null); then
        log INFO "  ├─ Mitsubishi MELSEC PLC detected (port 5007)"
    fi

    # Schneider Modicon (Port 502 + identification)
    # GE / Emerson (Various)
    for port in 18245 18246; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log INFO "  ├─ GE SRTP service detected (port $port)"
        fi
    done
}

# ── PLC Access Control ───────────────────────────────────────

check_plc_access_control() {
    local target="$1"
    echo -e "  ${CYAN}[Access Ctrl]${NC} Checking PLC access controls"

    # Check for open engineering ports
    local eng_ports=(
        "102:S7_Engineering"
        "502:Modbus_ReadWrite"
        "44818:EtherNetIP_Config"
        "2222:Schneider_Unity"
        "1089:Honeywell_CDA"
        "5007:Mitsubishi_MELSEC"
        "9600:Omron_FINS"
    )

    local open_count=0
    for entry in "${eng_ports[@]}"; do
        IFS=':' read -r port desc <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log CRIT "  ├─ ${desc} port $port OPEN — potential program access"
            ((open_count++))
        fi
    done

    if [[ $open_count -gt 2 ]]; then
        log CRIT "  ├─ $open_count engineering ports open — HIGH RISK exposure"
        echo -e "  ${RED}[!] Multiple PLC engineering ports are accessible.${NC}"
        echo -e "      ${RED}An attacker could read/modify ladder logic or firmware.${NC}"
    fi
}

# ── PLC Run/Program Mode ─────────────────────────────────────

check_plc_firmware_mode() {
    local target="$1"
    echo -e "  ${CYAN}[PLC Mode]${NC} Checking PLC operational mode"

    # Siemens S7: attempt to read SZL (System Status List)
    if (echo >/dev/tcp/"$target"/102 2>/dev/null); then
        log INFO "  ├─ Querying Siemens S7 CPU state..."
        # COTP Connection Request + S7 Setup Communication
        local cr_payload
        cr_payload=$(printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02')
        local resp
        resp=$(echo -ne "$cr_payload" | timeout 3 nc -w 2 "$target" 102 2>/dev/null | xxd -p || true)
        if [[ -n "$resp" ]]; then
            log WARN "  │  S7 connection established — CPU accessible"
            log WARN "  │  Check if PUT/GET is disabled in TIA Portal"
        fi
    fi

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Set PLC to RUN mode with key-switch where possible"
    echo -e "      • Enable CPU password protection"
    echo -e "      • Disable remote programming when not in maintenance"
    echo -e "      • Implement change detection on PLC programs"
}

# ── HMI Exposure ─────────────────────────────────────────────

check_hmi_exposure() {
    local target="$1"
    echo -e "  ${CYAN}[HMI]${NC} Checking HMI web exposure"

    local hmi_ports=(80 443 8080 8443 5900 5901 3389)
    for port in "${hmi_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            case $port in
                5900|5901)
                    log CRIT "  ├─ VNC (port $port) open — HMI may be remotely viewable"
                    echo -e "  ${RED}[!] VNC access to HMI is extremely dangerous.${NC}"
                    echo -e "      ${RED}Attacker could view & control physical processes.${NC}"
                    ;;
                3389)
                    log WARN "  ├─ RDP (port 3389) open — HMI workstation exposed"
                    ;;
                80|443|8080|8443)
                    local hmi_check
                    hmi_check=$(curl -sk --max-time 5 "http://${target}:${port}/" 2>/dev/null | head -100 || true)
                    if echo "$hmi_check" | grep -qi "scada\|hmi\|wonderware\|factorytalk\|ignition\|wincc\|citect\|genesis"; then
                        log CRIT "  ├─ HMI/SCADA web interface detected on port $port"
                    fi
                    ;;
            esac
        fi
    done
}

# ── RTU Configuration ────────────────────────────────────────

check_rtu_config() {
    local target="$1"
    echo -e "  ${CYAN}[RTU]${NC} Checking RTU security"

    # Common RTU serial-to-IP gateway ports
    local rtu_ports=(4001 4002 4003 7001 7002 50000 50001)
    for port in "${rtu_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log WARN "  ├─ Serial gateway port $port open — RTU may be accessible"
        fi
    done

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Encrypt RTU communications (VPN/TLS tunnel)"
    echo -e "      • Implement authentication on serial gateways"
    echo -e "      • Use application-layer whitelisting"
}

# ── Program Upload/Download Check ─────────────────────────────

check_program_upload() {
    local target="$1"
    echo -e "  ${CYAN}[Prog Access]${NC} Checking program transfer exposure"

    # TFTP (Port 69/UDP) - often used for firmware/config upload
    if command -v nmap &>/dev/null; then
        local tftp_check
        tftp_check=$(nmap -sU -p 69 "$target" 2>/dev/null | grep "69")
        if echo "$tftp_check" | grep -q "open"; then
            log CRIT "  ├─ TFTP (port 69/UDP) open — firmware/config upload possible"
            echo -e "  ${RED}[!] TFTP has NO authentication. Disable immediately.${NC}"
        fi
    fi

    # HTTP file upload endpoints
    if (echo >/dev/tcp/"$target"/80 2>/dev/null); then
        local upload_paths=("/upload" "/firmware" "/update" "/config/backup" "/cgi-bin/upload.cgi")
        for path in "${upload_paths[@]}"; do
            local resp_code
            resp_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://${target}${path}" 2>/dev/null || echo "000")
            if [[ "$resp_code" != "000" ]] && [[ "$resp_code" != "404" ]]; then
                log WARN "  ├─ Upload endpoint ${path} returned HTTP $resp_code"
            fi
        done
    fi
}
