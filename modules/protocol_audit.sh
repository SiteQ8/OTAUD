#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: Protocol Auditor
# Analyzes ICS/OT protocols for misconfigurations & exposure
# Supports: Modbus, DNP3, S7comm, EtherNet/IP, OPC-UA, BACnet,
#           MQTT, CoAP, FINS, HART-IP
# ═══════════════════════════════════════════════════════════════

run_protocol_audit() {
    local target="${1:?Usage: run_protocol_audit <target>}"
    log INFO "Protocol Audit — Target: $target"

    check_modbus "$target"
    check_dnp3 "$target"
    check_s7comm "$target"
    check_ethernetip "$target"
    check_opcua "$target"
    check_bacnet "$target"
    check_mqtt "$target"
    check_coap "$target"
    check_fins "$target"
    check_hartip "$target"

    log INFO "Protocol audit module completed."
}

# ── Modbus TCP (Port 502) ────────────────────────────────────

check_modbus() {
    local target="$1"
    echo -e "  ${CYAN}[Modbus TCP]${NC} Port 502"

    if (echo >/dev/tcp/"$target"/502 2>/dev/null); then
        log CRIT "Modbus TCP port 502 is OPEN on $target"
        log WARN "  ├─ Modbus has NO built-in authentication"
        log WARN "  ├─ Any device on the network can read/write registers"

        # Attempt to read device ID via nmap script
        if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
            local modbus_info
            modbus_info=$(nmap -sV -p 502 --script modbus-discover "$target" 2>/dev/null)
            if echo "$modbus_info" | grep -qi "modbus"; then
                log CRIT "  ├─ Modbus service CONFIRMED"
                echo "$modbus_info" | grep -E "^\|" | while read -r line; do
                    log INFO "  │  $line"
                done
            fi
        fi

        # Check for default Unit IDs
        log INFO "  ├─ Checking common Modbus Unit IDs (0, 1, 247, 255)..."
        for uid in 0 1 247 255; do
            local payload
            payload=$(printf '\x00\x01\x00\x00\x00\x06\x%02x\x03\x00\x00\x00\x01' "$uid")
            local resp
            resp=$(echo -ne "$payload" | timeout 2 nc -w 2 "$target" 502 2>/dev/null | xxd -p | head -c 40 || true)
            if [[ -n "$resp" ]] && [[ "$resp" != *"0000000003"* ]]; then
                log WARN "  │  Unit ID $uid responded: ${resp:0:40}"
            fi
        done

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Deploy Modbus-aware firewall (e.g., Tofino, Claroty)"
        echo -e "      • Restrict access via network segmentation"
        echo -e "      • Monitor for unauthorized function codes"
        echo -e "      • Consider Modbus/TCP security extensions (RFC draft)"
    else
        log INFO "  ├─ Port 502 closed — Modbus TCP not exposed"
    fi
}

# ── DNP3 (Port 20000) ────────────────────────────────────────

check_dnp3() {
    local target="$1"
    echo -e "  ${CYAN}[DNP3]${NC} Port 20000"

    if (echo >/dev/tcp/"$target"/20000 2>/dev/null); then
        log CRIT "DNP3 port 20000 is OPEN on $target"
        log WARN "  ├─ DNP3 Secure Authentication may not be enabled"

        if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
            nmap -sV -p 20000 --script dnp3-info "$target" 2>/dev/null | \
                grep -E "^\|" | while read -r line; do
                    log INFO "  │  $line"
                done
        fi

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Enable DNP3 Secure Authentication (SA v5)"
        echo -e "      • Restrict source addresses in outstation config"
        echo -e "      • Deploy DNP3-aware IDS rules"
        echo -e "      • Monitor for unsolicited responses"
    else
        log INFO "  ├─ Port 20000 closed — DNP3 not exposed"
    fi
}

# ── Siemens S7comm (Port 102) ─────────────────────────────────

check_s7comm() {
    local target="$1"
    echo -e "  ${CYAN}[S7comm]${NC} Port 102"

    if (echo >/dev/tcp/"$target"/102 2>/dev/null); then
        log CRIT "S7comm/ISO-TSAP port 102 is OPEN on $target"
        log WARN "  ├─ Siemens S7 protocol detected — often unprotected"

        if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
            nmap -sV -p 102 --script s7-info "$target" 2>/dev/null | \
                grep -E "^\|" | while read -r line; do
                    log INFO "  │  $line"
                done
        fi

        # Check for default S7 password (CPU protection level)
        log INFO "  ├─ Checking S7 CPU protection level..."
        local cotp_cr
        cotp_cr=$(printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02')
        local resp
        resp=$(echo -ne "$cotp_cr" | timeout 3 nc -w 2 "$target" 102 2>/dev/null | xxd -p | head -c 60 || true)
        if [[ -n "$resp" ]]; then
            log WARN "  │  S7 COTP responded — device is accessible"
        fi

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Set CPU protection level to 3 (full protection)"
        echo -e "      • Enable S7comm+ encrypted communication"
        echo -e "      • Block port 102 at OT firewall from IT network"
        echo -e "      • Disable PUT/GET access in TIA Portal"
    else
        log INFO "  ├─ Port 102 closed — S7comm not exposed"
    fi
}

# ── EtherNet/IP (Port 44818) ─────────────────────────────────

check_ethernetip() {
    local target="$1"
    echo -e "  ${CYAN}[EtherNet/IP]${NC} Port 44818"

    if (echo >/dev/tcp/"$target"/44818 2>/dev/null); then
        log CRIT "EtherNet/IP port 44818 is OPEN on $target"

        if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
            nmap -sV -p 44818 --script enip-info "$target" 2>/dev/null | \
                grep -E "^\|" | while read -r line; do
                    log INFO "  │  $line"
                done
        fi

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Implement CIP Security (TLS-based)"
        echo -e "      • Restrict EtherNet/IP to OT VLAN only"
        echo -e "      • Monitor for unauthorized CIP service requests"
    else
        log INFO "  ├─ Port 44818 closed — EtherNet/IP not exposed"
    fi
}

# ── OPC-UA (Port 4840) ───────────────────────────────────────

check_opcua() {
    local target="$1"
    echo -e "  ${CYAN}[OPC-UA]${NC} Port 4840"

    if (echo >/dev/tcp/"$target"/4840 2>/dev/null); then
        log WARN "OPC-UA port 4840 is OPEN on $target"

        # Check for anonymous authentication
        if command -v curl &>/dev/null; then
            local http_resp
            http_resp=$(curl -sk --max-time 5 "http://$target:4840" 2>/dev/null || true)
            if [[ -n "$http_resp" ]]; then
                log WARN "  ├─ OPC-UA HTTP endpoint responds — check security mode"
            fi
        fi

        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Enforce SignAndEncrypt security mode"
        echo -e "      • Disable anonymous authentication"
        echo -e "      • Use X.509 certificates for endpoint authentication"
        echo -e "      • Audit user access policies"
    else
        log INFO "  ├─ Port 4840 closed — OPC-UA not exposed"
    fi
}

# ── BACnet (Port 47808/UDP) ──────────────────────────────────

check_bacnet() {
    local target="$1"
    echo -e "  ${CYAN}[BACnet]${NC} Port 47808/UDP"

    if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
        local bacnet_info
        bacnet_info=$(nmap -sU -p 47808 --script bacnet-info "$target" 2>/dev/null)
        if echo "$bacnet_info" | grep -qi "bacnet"; then
            log CRIT "BACnet/IP detected on $target:47808"
            echo "$bacnet_info" | grep -E "^\|" | while read -r line; do
                log INFO "  │  $line"
            done
            echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
            echo -e "      • Implement BACnet Secure Connect (SC)"
            echo -e "      • Segment BACnet traffic from corporate LAN"
            echo -e "      • Disable BACnet/IP broadcast (use BBMD carefully)"
        fi
    else
        log INFO "  ├─ Skipping BACnet (requires nmap UDP scan)"
    fi
}

# ── MQTT (Port 1883/8883) ────────────────────────────────────

check_mqtt() {
    local target="$1"
    echo -e "  ${CYAN}[MQTT]${NC} Ports 1883/8883"

    for port in 1883 8883; do
        if (echo >/dev/tcp/"$target"/$port 2>/dev/null); then
            if [[ $port -eq 1883 ]]; then
                log CRIT "MQTT broker on $target:1883 (UNENCRYPTED)"
            else
                log WARN "MQTT/TLS on $target:8883"
            fi

            # Try anonymous CONNECT
            local mqtt_connect
            mqtt_connect=$(printf '\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03ota')
            local resp
            resp=$(echo -ne "$mqtt_connect" | timeout 3 nc -w 2 "$target" "$port" 2>/dev/null | xxd -p | head -c 20 || true)
            if [[ "$resp" == "20020000"* ]]; then
                log CRIT "  ├─ Anonymous MQTT connection ACCEPTED — no authentication!"
            elif [[ -n "$resp" ]]; then
                log INFO "  ├─ MQTT responded (may require credentials)"
            fi
        fi
    done

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Require username/password or client certificates"
    echo -e "      • Use MQTT over TLS (port 8883)"
    echo -e "      • Implement topic-based ACLs"
    echo -e "      • Disable \$SYS topic access for clients"
}

# ── CoAP (Port 5683/UDP) ─────────────────────────────────────

check_coap() {
    local target="$1"
    echo -e "  ${CYAN}[CoAP]${NC} Port 5683/UDP"

    if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
        local coap_result
        coap_result=$(nmap -sU -p 5683 "$target" 2>/dev/null | grep "5683")
        if echo "$coap_result" | grep -q "open"; then
            log WARN "CoAP port 5683/UDP open on $target"
            echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
            echo -e "      • Use DTLS for CoAP encryption"
            echo -e "      • Implement OSCORE object security"
            echo -e "      • Restrict CoAP resource discovery"
        fi
    fi
}

# ── FINS (Port 9600) ─────────────────────────────────────────

check_fins() {
    local target="$1"
    echo -e "  ${CYAN}[FINS/Omron]${NC} Port 9600"

    if (echo >/dev/tcp/"$target"/9600 2>/dev/null); then
        log CRIT "Omron FINS port 9600 is OPEN on $target"
        log WARN "  ├─ FINS protocol has NO authentication mechanism"
        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Isolate Omron PLCs on dedicated VLAN"
        echo -e "      • Deploy FINS-aware DPI firewall"
        echo -e "      • Monitor for unauthorized memory read/write"
    else
        log INFO "  ├─ Port 9600 closed — FINS not exposed"
    fi
}

# ── HART-IP (Port 5094) ──────────────────────────────────────

check_hartip() {
    local target="$1"
    echo -e "  ${CYAN}[HART-IP]${NC} Port 5094"

    if (echo >/dev/tcp/"$target"/5094 2>/dev/null); then
        log WARN "HART-IP port 5094 is OPEN on $target"
        echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
        echo -e "      • Restrict HART-IP to maintenance VLAN"
        echo -e "      • Audit HART device configurations regularly"
    else
        log INFO "  ├─ Port 5094 closed — HART-IP not exposed"
    fi
}
