#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: Configuration Auditor
# Checks for misconfigurations, weak settings, default creds
# ═══════════════════════════════════════════════════════════════

run_config_audit() {
    local target="${1:?Usage: run_config_audit <target>}"
    log INFO "Configuration Audit — Target: $target"

    check_default_credentials "$target"
    check_web_interfaces "$target"
    check_snmp "$target"
    check_telnet_ssh "$target"
    check_ftp "$target"
    check_ntp "$target"
    check_dns "$target"
    check_tls_config "$target"

    log INFO "Configuration audit module completed."
}

# ── Default Credentials Check ─────────────────────────────────

check_default_credentials() {
    local target="$1"
    echo -e "  ${CYAN}[Default Creds]${NC} Checking common OT default credentials"

    # Common OT default credential pairs (vendor:user:pass:port)
    local creds=(
        "Siemens_S7:admin:admin:80"
        "Siemens_WinCC:administrator::80"
        "Schneider_M340:USER:USER:80"
        "Schneider_Quantum:USER:USER:80"
        "ABB_AC500:admin:admin:80"
        "Rockwell_EWS:admin:1234:80"
        "Moxa_Serial:admin::80"
        "Moxa_Switch:admin::80"
        "Advantech_WebAccess:admin::80"
        "GE_CIMPLICITY:admin:admin:80"
        "Honeywell_Experion:MANAGER:MANAGER:80"
        "Yokogawa_Centum:CENTUM:CENTUM:80"
        "Phoenix_Contact:admin:admin:80"
        "WAGO:admin:wago:80"
        "HMS_Anybus:admin:admin:80"
        "Telnet_default:admin:admin:23"
        "Telnet_default:root:root:23"
        "Telnet_default:user:user:23"
    )

    for entry in "${creds[@]}"; do
        IFS=':' read -r vendor user pass port <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            if [[ $port -eq 80 ]] || [[ $port -eq 443 ]] || [[ $port -eq 8080 ]]; then
                local http_code
                http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --max-time 5 \
                    -u "${user}:${pass}" \
                    "http://${target}:${port}/" 2>/dev/null || echo "000")
                if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
                    log CRIT "  ├─ ${vendor}: Default creds ${user}:${pass} ACCEPTED on port $port!"
                fi
            elif [[ $port -eq 23 ]]; then
                log WARN "  ├─ ${vendor}: Telnet open — manual check needed for ${user}:${pass}"
            fi
        fi
    done
}

# ── Web Interface Checks ─────────────────────────────────────

check_web_interfaces() {
    local target="$1"
    echo -e "  ${CYAN}[Web Interfaces]${NC} Checking HMI/SCADA web panels"

    local web_ports=(80 443 8080 8443 8888 9090 4443 8000 3000)
    for port in "${web_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log WARN "  ├─ Web interface found on port $port"

            # Check for missing security headers
            local headers
            headers=$(curl -skI --max-time 5 "http://${target}:${port}/" 2>/dev/null || true)

            if [[ -n "$headers" ]]; then
                local server
                server=$(echo "$headers" | grep -i "^Server:" | head -1)
                [[ -n "$server" ]] && log INFO "  │  Server: $server"

                # Security headers check
                local missing_headers=()
                echo "$headers" | grep -qi "X-Frame-Options" || missing_headers+=("X-Frame-Options")
                echo "$headers" | grep -qi "Content-Security-Policy" || missing_headers+=("Content-Security-Policy")
                echo "$headers" | grep -qi "X-Content-Type-Options" || missing_headers+=("X-Content-Type-Options")
                echo "$headers" | grep -qi "Strict-Transport-Security" || missing_headers+=("HSTS")
                echo "$headers" | grep -qi "X-XSS-Protection" || missing_headers+=("X-XSS-Protection")

                if [[ ${#missing_headers[@]} -gt 0 ]]; then
                    log WARN "  │  Missing security headers: ${missing_headers[*]}"
                fi

                # Check for directory listing
                local body
                body=$(curl -sk --max-time 5 "http://${target}:${port}/" 2>/dev/null | head -50 || true)
                if echo "$body" | grep -qi "Index of /\|directory listing\|parent directory"; then
                    log CRIT "  │  Directory listing ENABLED — information disclosure risk"
                fi
            fi
        fi
    done
}

# ── SNMP Check ────────────────────────────────────────────────

check_snmp() {
    local target="$1"
    echo -e "  ${CYAN}[SNMP]${NC} Checking SNMP configuration"

    if command -v snmpwalk &>/dev/null; then
        # Test default community strings
        local communities=("public" "private" "admin" "manager" "snmp" "monitor" "community")
        for comm in "${communities[@]}"; do
            local result
            result=$(timeout 5 snmpwalk -v2c -c "$comm" "$target" 1.3.6.1.2.1.1.1 2>/dev/null | head -1 || true)
            if [[ -n "$result" ]]; then
                log CRIT "  ├─ SNMP community '$comm' is ACCESSIBLE on $target"
                log INFO "  │  SysDescr: $result"
            fi
        done

        # Check for SNMPv3
        local v3_test
        v3_test=$(timeout 5 snmpwalk -v3 -l noAuthNoPriv -u "" "$target" 1.3.6.1.2.1.1.1 2>/dev/null || true)
        if [[ -n "$v3_test" ]]; then
            log WARN "  ├─ SNMPv3 with noAuthNoPriv allowed — upgrade to authPriv"
        fi
    else
        # Fallback: check if SNMP port is open
        if command -v nmap &>/dev/null; then
            nmap -sU -p 161 "$target" 2>/dev/null | grep -q "open" && \
                log WARN "  ├─ SNMP port 161/UDP is open (install snmp tools for deeper check)"
        fi
    fi

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Disable SNMPv1/v2c, use SNMPv3 with authPriv"
    echo -e "      • Change all default community strings"
    echo -e "      • Restrict SNMP access via ACLs"
}

# ── Telnet / SSH Check ────────────────────────────────────────

check_telnet_ssh() {
    local target="$1"
    echo -e "  ${CYAN}[Remote Access]${NC} Checking Telnet & SSH"

    # Telnet
    if (echo >/dev/tcp/"$target"/23 2>/dev/null); then
        log CRIT "  ├─ Telnet (port 23) is OPEN — unencrypted remote access!"
        echo -e "  ${RED}[!] Disable Telnet immediately. Use SSH instead.${NC}"
    fi

    # SSH
    if (echo >/dev/tcp/"$target"/22 2>/dev/null); then
        log INFO "  ├─ SSH (port 22) is open"

        if command -v ssh &>/dev/null; then
            local ssh_banner
            ssh_banner=$(timeout 3 bash -c "echo '' | nc -w 2 $target 22" 2>/dev/null | head -1 || true)
            if [[ -n "$ssh_banner" ]]; then
                log INFO "  │  SSH Banner: $ssh_banner"

                # Check for old SSH versions
                if echo "$ssh_banner" | grep -qE "SSH-1\.|dropbear_0\.[0-4]|OpenSSH_[1-6]\."; then
                    log CRIT "  │  OUTDATED SSH version detected — upgrade immediately"
                fi
            fi
        fi
    fi
}

# ── FTP Check ─────────────────────────────────────────────────

check_ftp() {
    local target="$1"
    echo -e "  ${CYAN}[FTP]${NC} Checking FTP configuration"

    if (echo >/dev/tcp/"$target"/21 2>/dev/null); then
        log WARN "  ├─ FTP (port 21) is OPEN"

        # Check anonymous login
        local ftp_resp
        ftp_resp=$(timeout 5 bash -c "
            exec 3<>/dev/tcp/$target/21
            read -r banner <&3
            echo 'USER anonymous' >&3
            read -r resp1 <&3
            echo 'PASS anonymous@' >&3
            read -r resp2 <&3
            echo \"\$resp2\"
            exec 3>&-
        " 2>/dev/null || true)

        if echo "$ftp_resp" | grep -q "^230"; then
            log CRIT "  ├─ Anonymous FTP login ACCEPTED!"
        fi

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Replace FTP with SFTP/SCP"
        echo -e "      • Disable anonymous access"
        echo -e "      • If FTP required, enforce FTPS (TLS)"
    fi
}

# ── NTP Check ─────────────────────────────────────────────────

check_ntp() {
    local target="$1"
    echo -e "  ${CYAN}[NTP]${NC} Checking time synchronization"

    if command -v ntpdate &>/dev/null; then
        local ntp_resp
        ntp_resp=$(timeout 5 ntpdate -q "$target" 2>/dev/null || true)
        if [[ -n "$ntp_resp" ]]; then
            log INFO "  ├─ NTP responding on $target"
            local offset
            offset=$(echo "$ntp_resp" | grep "offset" | awk '{print $(NF-1)}')
            if [[ -n "$offset" ]]; then
                local abs_offset
                abs_offset=$(echo "$offset" | tr -d '-')
                if (( $(echo "$abs_offset > 1.0" | bc -l 2>/dev/null || echo 0) )); then
                    log WARN "  ├─ Time offset > 1s ($offset sec) — may affect log correlation"
                fi
            fi
        fi
    fi
}

# ── DNS Check ─────────────────────────────────────────────────

check_dns() {
    local target="$1"
    echo -e "  ${CYAN}[DNS]${NC} Checking DNS configuration"

    if (echo >/dev/tcp/"$target"/53 2>/dev/null); then
        log WARN "  ├─ DNS (port 53) is open on $target"

        if command -v dig &>/dev/null; then
            # Check for zone transfer
            local axfr
            axfr=$(dig @"$target" AXFR 2>/dev/null | head -5 || true)
            if echo "$axfr" | grep -qv "Transfer failed\|REFUSED\|SERVFAIL"; then
                log CRIT "  ├─ DNS zone transfer MAY be allowed — investigate"
            fi

            # Check for open recursion
            local recursion
            recursion=$(dig @"$target" google.com +short 2>/dev/null || true)
            if [[ -n "$recursion" ]]; then
                log WARN "  ├─ Open DNS recursion detected"
            fi
        fi
    fi
}

# ── TLS Configuration ────────────────────────────────────────

check_tls_config() {
    local target="$1"
    echo -e "  ${CYAN}[TLS/SSL]${NC} Checking encryption configuration"

    local tls_ports=(443 8443 4443 993 995 636)
    for port in "${tls_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log INFO "  ├─ TLS service on port $port"

            if command -v openssl &>/dev/null; then
                local cert_info
                cert_info=$(echo | timeout 5 openssl s_client -connect "$target:$port" 2>/dev/null)

                # Check certificate expiry
                local expiry
                expiry=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
                if [[ -n "$expiry" ]]; then
                    local exp_epoch now_epoch
                    exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
                    now_epoch=$(date +%s)
                    if [[ $exp_epoch -lt $now_epoch ]]; then
                        log CRIT "  │  Certificate EXPIRED: $expiry"
                    elif [[ $((exp_epoch - now_epoch)) -lt 2592000 ]]; then
                        log WARN "  │  Certificate expiring soon: $expiry"
                    fi
                fi

                # Check for weak protocols
                for proto in ssl2 ssl3 tls1; do
                    local weak_test
                    weak_test=$(echo | timeout 3 openssl s_client -connect "$target:$port" -"$proto" 2>&1 || true)
                    if echo "$weak_test" | grep -q "CONNECTED" && ! echo "$weak_test" | grep -q "alert\|error"; then
                        log CRIT "  │  WEAK protocol supported: $proto"
                    fi
                done

                # Check for self-signed
                if echo "$cert_info" | grep -q "self-signed\|verify error:num=18"; then
                    log WARN "  │  Self-signed certificate detected"
                fi
            fi
        fi
    done
}
