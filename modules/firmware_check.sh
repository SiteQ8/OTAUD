#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: Firmware Analyzer
# Checks firmware versions, known CVEs, and integrity
# ═══════════════════════════════════════════════════════════════

run_firmware_check() {
    local target="${1:?Usage: run_firmware_check <target>}"
    log INFO "Firmware Analysis — Target: $target"

    extract_firmware_versions "$target"
    check_known_vulnerable_versions "$target"
    check_firmware_integrity "$target"
    check_debug_interfaces "$target"
    check_bootloader_security "$target"

    log INFO "Firmware analysis module completed."
}

# ── Extract Firmware Versions ─────────────────────────────────

extract_firmware_versions() {
    local target="$1"
    echo -e "  ${CYAN}[FW Version]${NC} Extracting firmware/software versions"

    # HTTP-based version discovery
    for port in 80 443 8080 8443; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local body headers
            headers=$(curl -skI --max-time 5 "http://${target}:${port}/" 2>/dev/null || true)
            body=$(curl -sk --max-time 5 "http://${target}:${port}/" 2>/dev/null | head -500 || true)

            # Server header
            local server
            server=$(echo "$headers" | grep -i "^Server:" | head -1 | tr -d '\r')
            [[ -n "$server" ]] && log INFO "  ├─ $server"

            # X-Powered-By
            local powered
            powered=$(echo "$headers" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r')
            [[ -n "$powered" ]] && log INFO "  ├─ $powered"

            # Version strings in body
            local versions
            versions=$(echo "$body" | grep -oiE '(firmware|version|fw|sw|rev)[:\s]*v?[0-9]+\.[0-9]+[\.0-9]*' | head -5)
            if [[ -n "$versions" ]]; then
                echo "$versions" | while read -r v; do
                    log INFO "  ├─ Detected: $v"
                done
            fi

            # Common version API endpoints
            for api in "/api/version" "/api/system/info" "/api/v1/status" "/system/info" "/info.json" "/api/info"; do
                local api_resp
                api_resp=$(curl -sk --max-time 3 "http://${target}:${port}${api}" 2>/dev/null | head -50 || true)
                if [[ -n "$api_resp" ]] && echo "$api_resp" | grep -qi "version\|firmware\|model"; then
                    log INFO "  ├─ API ${api}: ${api_resp:0:120}"
                fi
            done
            break
        fi
    done

    # SNMP-based version extraction
    if command -v snmpwalk &>/dev/null; then
        local sys_descr
        sys_descr=$(timeout 5 snmpwalk -v2c -c public "$target" 1.3.6.1.2.1.1.1.0 2>/dev/null | head -1 || true)
        if [[ -n "$sys_descr" ]]; then
            log INFO "  ├─ SNMP SysDescr: ${sys_descr:0:120}"
        fi
    fi

    # SSH banner
    if (echo >/dev/tcp/"$target"/22 2>/dev/null); then
        local ssh_banner
        ssh_banner=$(timeout 3 bash -c "echo '' | nc -w 2 $target 22" 2>/dev/null | head -1 || true)
        [[ -n "$ssh_banner" ]] && log INFO "  ├─ SSH: $ssh_banner"
    fi
}

# ── Known Vulnerable Versions ────────────────────────────────

check_known_vulnerable_versions() {
    local target="$1"
    echo -e "  ${CYAN}[CVE Check]${NC} Checking for known vulnerable firmware"

    # Known vulnerable OT firmware patterns
    local vuln_patterns=(
        "Siemens.*V[1-3]\.:CVE-2019-13945:S7-1500 CPU bypass"
        "WinCC.*V7\.[0-3]:CVE-2019-18306:WinCC RCE"
        "Modicon.*V2\.[0-8]:CVE-2018-7760:Schneider auth bypass"
        "MicroLogix.*1100.*Series.*[AB]:CVE-2017-12088:AB buffer overflow"
        "FactoryTalk.*V[1-8]\.:CVE-2020-12034:Rockwell RCE"
        "Ignition.*7\.:CVE-2020-10644:Ignition deserialization"
        "Advantech.*WebAccess.*[1-8]\.:CVE-2021-22669:Advantech RCE"
        "Moxa.*NPort.*[1-3]\.:CVE-2020-25198:Moxa command injection"
        "OpenSSH_[1-6]\.:CVE-various:Outdated SSH"
        "Apache/2\.2\.:CVE-various:Outdated Apache"
        "nginx/1\.[0-9]\.:CVE-various:Outdated nginx"
        "Dropbear.*201[0-8]:CVE-various:Outdated Dropbear SSH"
    )

    # Gather all version strings
    local all_versions=""
    for port in 80 443 22 8080; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local info
            if [[ $port -eq 22 ]]; then
                info=$(timeout 3 bash -c "echo '' | nc -w 2 $target 22" 2>/dev/null | head -1 || true)
            else
                info=$(curl -skI --max-time 3 "http://${target}:${port}/" 2>/dev/null || true)
            fi
            all_versions+="$info "
        fi
    done

    if [[ -n "$all_versions" ]]; then
        for pattern_entry in "${vuln_patterns[@]}"; do
            IFS=':' read -r pattern cve desc <<< "$pattern_entry"
            if echo "$all_versions" | grep -qiE "$pattern"; then
                log CRIT "  ├─ VULNERABLE: $desc ($cve)"
            fi
        done
    fi

    # Suggest CVE lookup tool
    if [[ -f "${PYTHON_DIR}/cve_lookup.py" ]]; then
        log INFO "  ├─ For detailed CVE lookup, run: python3 python/cve_lookup.py --query <vendor>"
    fi
}

# ── Firmware Integrity ────────────────────────────────────────

check_firmware_integrity() {
    local target="$1"
    echo -e "  ${CYAN}[Integrity]${NC} Checking firmware integrity mechanisms"

    # Check for unsigned firmware upload endpoints
    for port in 80 8080; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local upload_test
            upload_test=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
                "http://${target}:${port}/firmware/upload" 2>/dev/null || echo "000")
            if [[ "$upload_test" != "000" ]] && [[ "$upload_test" != "404" ]]; then
                log WARN "  ├─ Firmware upload endpoint accessible (HTTP $upload_test)"
                echo -e "  ${RED}[!] Check if firmware signature validation is enforced.${NC}"
            fi
        fi
    done

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Enable secure boot / firmware signature verification"
    echo -e "      • Maintain firmware hash inventory for change detection"
    echo -e "      • Subscribe to ICS-CERT / vendor advisories"
}

# ── Debug Interfaces ──────────────────────────────────────────

check_debug_interfaces() {
    local target="$1"
    echo -e "  ${CYAN}[Debug]${NC} Checking for exposed debug interfaces"

    local debug_ports=(
        "2323:Alt_Telnet/Debug"
        "4444:Debug_Shell"
        "6666:Debug_Port"
        "7777:Debug_Port"
        "9999:Debug_Port"
        "31337:Backdoor"
        "1234:Debug_Serial"
        "5555:ADB_Android"
        "8000:Debug_HTTP"
    )

    for entry in "${debug_ports[@]}"; do
        IFS=':' read -r port desc <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log CRIT "  ├─ ${desc} port $port OPEN — possible debug/backdoor interface"
        fi
    done

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Disable all debug interfaces in production"
    echo -e "      • Disable JTAG/UART debug headers physically"
    echo -e "      • Monitor for unauthorized port openings"
}

# ── Bootloader Security ──────────────────────────────────────

check_bootloader_security() {
    local target="$1"
    echo -e "  ${CYAN}[Bootloader]${NC} Bootloader & recovery mode checks"

    # TFTP (used for bootloader recovery)
    if command -v nmap &>/dev/null; then
        local tftp
        tftp=$(nmap -sU -p 69 "$target" 2>/dev/null | grep "69")
        if echo "$tftp" | grep -q "open"; then
            log CRIT "  ├─ TFTP (port 69/UDP) OPEN — bootloader file transfer possible"
            echo -e "  ${RED}[!] Attacker could push malicious firmware via TFTP.${NC}"
        fi
    fi

    # BootP (Port 67-68/UDP)
    if command -v nmap &>/dev/null; then
        local bootp
        bootp=$(nmap -sU -p 67,68 "$target" 2>/dev/null | grep "open")
        if [[ -n "$bootp" ]]; then
            log WARN "  ├─ BootP ports open — device may accept network boot"
        fi
    fi
}
