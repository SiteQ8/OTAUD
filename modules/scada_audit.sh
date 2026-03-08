#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: SCADA System Auditor
# Comprehensive SCADA security assessment
# ═══════════════════════════════════════════════════════════════

run_scada_audit() {
    local target="${1:?Usage: run_scada_audit <target>}"
    log INFO "SCADA Audit — Target: $target"

    check_scada_web_servers "$target"
    check_scada_databases "$target"
    check_historian "$target"
    check_scada_protocols "$target"
    check_remote_access_scada "$target"
    check_scada_network_segmentation "$target"

    log INFO "SCADA audit module completed."
}

# ── SCADA Web Servers ─────────────────────────────────────────

check_scada_web_servers() {
    local target="$1"
    echo -e "  ${CYAN}[SCADA Web]${NC} Identifying SCADA web platforms"

    local web_ports=(80 443 8080 8443 8088 9090 8888 4911)
    for port in "${web_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local body headers
            headers=$(curl -skI --max-time 5 "http://${target}:${port}/" 2>/dev/null || true)
            body=$(curl -sk --max-time 5 "http://${target}:${port}/" 2>/dev/null | head -200 || true)

            # Detect SCADA platforms by fingerprint
            local detected=""
            if echo "$body$headers" | grep -qi "ignition"; then
                detected="Inductive Automation Ignition"
            elif echo "$body$headers" | grep -qi "wonderware\|aveva"; then
                detected="AVEVA/Wonderware"
            elif echo "$body$headers" | grep -qi "factorytalk"; then
                detected="Rockwell FactoryTalk"
            elif echo "$body$headers" | grep -qi "wincc\|simatic"; then
                detected="Siemens WinCC"
            elif echo "$body$headers" | grep -qi "citect"; then
                detected="Schneider CitectSCADA"
            elif echo "$body$headers" | grep -qi "genesis\|iconics"; then
                detected="ICONICS Genesis64"
            elif echo "$body$headers" | grep -qi "vtscada"; then
                detected="VTScada"
            elif echo "$body$headers" | grep -qi "realflex"; then
                detected="RealFlex SCADA"
            elif echo "$body$headers" | grep -qi "webaccess"; then
                detected="Advantech WebAccess"
            fi

            if [[ -n "$detected" ]]; then
                log CRIT "  ├─ ${detected} detected on port $port"
                log WARN "  │  SCADA web interfaces should NEVER be internet-facing"
            fi

            # Check for known CVE patterns in headers
            local server_header
            server_header=$(echo "$headers" | grep -i "^Server:" || true)
            if [[ -n "$server_header" ]]; then
                log INFO "  │  $server_header"
                # Flag known-vulnerable servers
                if echo "$server_header" | grep -qi "Apache/2\.2\|IIS/6\|IIS/7\.0\|nginx/1\.[0-9]\."; then
                    log WARN "  │  Potentially outdated web server version"
                fi
            fi
        fi
    done
}

# ── SCADA Databases ───────────────────────────────────────────

check_scada_databases() {
    local target="$1"
    echo -e "  ${CYAN}[SCADA DB]${NC} Checking database exposure"

    local db_checks=(
        "1433:MSSQL:Microsoft SQL Server (common in SCADA)"
        "1521:Oracle:Oracle DB (common in Honeywell/Yokogawa)"
        "3306:MySQL:MySQL/MariaDB"
        "5432:PostgreSQL:PostgreSQL (common in Ignition)"
        "27017:MongoDB:MongoDB (NoSQL exposure)"
        "6379:Redis:Redis (in-memory store)"
    )

    for entry in "${db_checks[@]}"; do
        IFS=':' read -r port name desc <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log CRIT "  ├─ ${name} port $port OPEN — ${desc}"
            log WARN "  │  Database should not be directly accessible from OT network"

            # Try banner grab
            local banner
            banner=$(timeout 3 bash -c "echo '' | nc -w 2 $target $port" 2>/dev/null | strings | head -1 || true)
            [[ -n "$banner" ]] && log INFO "  │  Banner: ${banner:0:80}"
        fi
    done

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Isolate SCADA databases on dedicated network segment"
    echo -e "      • Enforce strong authentication, no default SA passwords"
    echo -e "      • Enable TLS for all database connections"
    echo -e "      • Implement database activity monitoring"
}

# ── Historian Server Check ────────────────────────────────────

check_historian() {
    local target="$1"
    echo -e "  ${CYAN}[Historian]${NC} Checking process historian exposure"

    # OSIsoft PI (now AVEVA PI)
    local pi_ports=(5450 5457 5459 5460 5461)
    for port in "${pi_ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log WARN "  ├─ AVEVA/OSIsoft PI port $port open"
        fi
    done

    # Honeywell PHD
    if (echo >/dev/tcp/"$target"/3200 2>/dev/null); then
        log WARN "  ├─ Honeywell PHD historian port 3200 open"
    fi

    # GE Proficy Historian
    if (echo >/dev/tcp/"$target"/14000 2>/dev/null); then
        log WARN "  ├─ GE Proficy Historian port 14000 open"
    fi

    # Check OPC-HDA (Historical Data Access)
    if (echo >/dev/tcp/"$target"/135 2>/dev/null); then
        log WARN "  ├─ DCOM/RPC (port 135) open — may expose OPC-HDA"
    fi
}

# ── SCADA Protocol Layer ─────────────────────────────────────

check_scada_protocols() {
    local target="$1"
    echo -e "  ${CYAN}[SCADA Proto]${NC} Checking SCADA-specific protocols"

    # IEC 60870-5-104 (Port 2404)
    if (echo >/dev/tcp/"$target"/2404 2>/dev/null); then
        log CRIT "  ├─ IEC 104 (port 2404) OPEN — power grid protocol exposed"
        echo -e "  ${RED}[!] IEC 104 has no built-in security. Must be tunneled.${NC}"
    fi

    # IEC 61850 MMS (Port 102)
    if (echo >/dev/tcp/"$target"/102 2>/dev/null); then
        log WARN "  ├─ IEC 61850/MMS (port 102) open"
    fi

    # ICCP/TASE.2 (Port 102, different context)
    # OPC Classic DCOM
    if (echo >/dev/tcp/"$target"/135 2>/dev/null); then
        log WARN "  ├─ OPC Classic DCOM (port 135) — legacy, insecure"
        echo -e "  ${RED}[!] Migrate from OPC Classic to OPC-UA with security.${NC}"
    fi
}

# ── Remote Access to SCADA ────────────────────────────────────

check_remote_access_scada() {
    local target="$1"
    echo -e "  ${CYAN}[Remote]${NC} Checking remote access vectors"

    local remote_ports=(
        "22:SSH"
        "23:Telnet"
        "3389:RDP"
        "5900:VNC"
        "5901:VNC_Alt"
        "4899:Radmin"
        "5938:TeamViewer"
        "8200:GoToMyPC"
        "443:HTTPS_VPN"
        "1194:OpenVPN"
        "500:IKE_VPN"
    )

    local remote_count=0
    for entry in "${remote_ports[@]}"; do
        IFS=':' read -r port desc <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log WARN "  ├─ ${desc} (port $port) accessible"
            ((remote_count++))
        fi
    done

    if [[ $remote_count -gt 3 ]]; then
        log CRIT "  ├─ ${remote_count} remote access services detected — excessive exposure"
    fi

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Use a single, audited jump host for all remote access"
    echo -e "      • Enforce MFA for all remote connections"
    echo -e "      • Implement session recording for forensic capability"
    echo -e "      • Disable direct RDP/VNC — use VPN + bastion host"
}

# ── Network Segmentation Validation ──────────────────────────

check_scada_network_segmentation() {
    local target="$1"
    echo -e "  ${CYAN}[Segmentation]${NC} Testing network segmentation"

    # Check if IT-common services are reachable from OT target
    local it_services=(
        "53:DNS"
        "80:HTTP"
        "443:HTTPS"
        "389:LDAP"
        "445:SMB"
        "3389:RDP"
        "8080:HTTP_Proxy"
    )

    local it_reachable=0
    for entry in "${it_services[@]}"; do
        IFS=':' read -r port desc <<< "$entry"
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            ((it_reachable++))
        fi
    done

    if [[ $it_reachable -gt 4 ]]; then
        log CRIT "  ├─ $it_reachable IT services reachable — poor OT/IT segmentation"
        echo -e "  ${RED}[!] Implement Purdue model zones with firewalls/DMZ.${NC}"
    elif [[ $it_reachable -gt 0 ]]; then
        log WARN "  ├─ $it_reachable IT services reachable — verify segmentation policy"
    else
        log INFO "  ├─ Good: No common IT services exposed on OT target"
    fi
}
