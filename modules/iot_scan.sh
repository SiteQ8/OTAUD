#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: IoT Device Scanner
# Discovers and audits IoT devices in OT environments
# ═══════════════════════════════════════════════════════════════

run_iot_scan() {
    local target="${1:?Usage: run_iot_scan <target>}"
    log INFO "IoT Discovery & Audit — Target: $target"

    discover_iot_devices "$target"
    check_iot_protocols "$target"
    check_iot_web_interfaces "$target"
    check_iot_default_creds "$target"
    check_upnp_exposure "$target"
    check_iot_update_channels "$target"

    log INFO "IoT scan module completed."
}

# ── IoT Device Discovery ─────────────────────────────────────

discover_iot_devices() {
    local target="$1"
    echo -e "  ${CYAN}[Discovery]${NC} Enumerating IoT devices"

    # mDNS / Bonjour discovery
    if command -v avahi-browse &>/dev/null; then
        log INFO "  ├─ Running mDNS discovery..."
        timeout 10 avahi-browse -art 2>/dev/null | head -30 | while read -r line; do
            log INFO "  │  $line"
        done
    fi

    # IoT-common ports scan
    local iot_ports="80,443,1883,5683,8080,8443,8883,4840,6668,9100,515,631,23,22,21"
    if command -v nmap &>/dev/null && [[ $DRY_RUN -eq 0 ]]; then
        log INFO "  ├─ Scanning IoT-common ports..."
        nmap -sV -p "$iot_ports" --open "$target" 2>/dev/null | grep "open" | while read -r line; do
            log INFO "  │  $line"
        done
    fi

    # Identify IoT device types by service fingerprint
    for port in 9100 515 631; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            log WARN "  ├─ Network printer/IoT device (port $port) detected"
        fi
    done

    # IP cameras (common RTSP)
    if (echo >/dev/tcp/"$target"/554 2>/dev/null); then
        log WARN "  ├─ RTSP stream (port 554) — IP camera likely"
    fi

    # Check for Zigbee/Z-Wave gateways (HTTP interfaces)
    for port in 8081 8082 8123; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local body
            body=$(curl -sk --max-time 3 "http://${target}:${port}/" 2>/dev/null | head -50 || true)
            if echo "$body" | grep -qi "home.assistant\|hubitat\|smartthings\|zigbee\|z-wave\|openhab\|domoticz"; then
                log WARN "  ├─ IoT hub/gateway detected on port $port"
            fi
        fi
    done
}

# ── IoT Protocol Checks ──────────────────────────────────────

check_iot_protocols() {
    local target="$1"
    echo -e "  ${CYAN}[IoT Protocols]${NC} Checking IoT communication protocols"

    # MQTT (1883 unencrypted / 8883 TLS)
    if (echo >/dev/tcp/"$target"/1883 2>/dev/null); then
        log CRIT "  ├─ MQTT broker (port 1883) UNENCRYPTED"

        # Try anonymous subscribe to wildcard
        local mqtt_connect
        mqtt_connect=$(printf '\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03ota')
        local resp
        resp=$(echo -ne "$mqtt_connect" | timeout 3 nc -w 2 "$target" 1883 2>/dev/null | xxd -p | head -c 20 || true)
        if [[ "$resp" == "20020000"* ]]; then
            log CRIT "  │  Anonymous access ALLOWED — full topic exposure"
            echo -e "  ${RED}[!] Anyone can subscribe to # and read ALL messages.${NC}"
        fi
    fi

    # CoAP (5683/UDP)
    if command -v nmap &>/dev/null; then
        local coap
        coap=$(nmap -sU -p 5683 "$target" 2>/dev/null | grep "5683")
        if echo "$coap" | grep -q "open"; then
            log WARN "  ├─ CoAP (port 5683/UDP) open"
            log INFO "  │  Check if DTLS is enforced for CoAP security"
        fi
    fi

    # AMQP (5672)
    if (echo >/dev/tcp/"$target"/5672 2>/dev/null); then
        log WARN "  ├─ AMQP broker (port 5672) detected"
    fi

    # XMPP IoT (5222)
    if (echo >/dev/tcp/"$target"/5222 2>/dev/null); then
        log INFO "  ├─ XMPP (port 5222) — possible IoT messaging"
    fi
}

# ── IoT Web Interfaces ───────────────────────────────────────

check_iot_web_interfaces() {
    local target="$1"
    echo -e "  ${CYAN}[IoT Web]${NC} Checking IoT device web panels"

    local ports=(80 443 8080 8443 8888 8000 3000 4200)
    for port in "${ports[@]}"; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            local body
            body=$(curl -sk --max-time 5 "http://${target}:${port}/" 2>/dev/null | head -200 || true)
            local title
            title=$(echo "$body" | grep -oP '(?<=<title>).*?(?=</title>)' | head -1 || true)

            if [[ -n "$title" ]]; then
                log INFO "  ├─ Port $port title: $title"
            fi

            # Detect common IoT platforms
            if echo "$body" | grep -qi "camera\|ipcam\|hikvision\|dahua\|axis\|foscam\|amcrest"; then
                log CRIT "  │  IP Camera web interface detected"
            elif echo "$body" | grep -qi "router\|gateway\|modem\|access.point"; then
                log WARN "  │  Network device admin panel detected"
            elif echo "$body" | grep -qi "printer\|cups\|xerox\|hp\|canon\|brother"; then
                log WARN "  │  Printer admin interface detected"
            fi

            # Check for API endpoints
            for api_path in "/api" "/api/v1" "/rest" "/json" "/cgi-bin"; do
                local api_code
                api_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://${target}:${port}${api_path}" 2>/dev/null || echo "000")
                if [[ "$api_code" == "200" ]]; then
                    log WARN "  │  API endpoint found: ${api_path} (HTTP $api_code)"
                fi
            done
        fi
    done
}

# ── IoT Default Credentials ──────────────────────────────────

check_iot_default_creds() {
    local target="$1"
    echo -e "  ${CYAN}[IoT Creds]${NC} Checking for default IoT credentials"

    local iot_creds=(
        "admin:admin:Generic"
        "admin:password:Generic"
        "admin:1234:Generic"
        "admin::Moxa/Various"
        "root:root:Linux_IoT"
        "root:toor:Linux_IoT"
        "admin:123456:Camera"
        "admin:12345:Hikvision"
        "admin:admin123:Various"
        "user:user:Generic"
        "pi:raspberry:Raspberry_Pi"
        "ubnt:ubnt:Ubiquiti"
    )

    for port in 80 8080 443; do
        if (echo >/dev/tcp/"$target"/"$port" 2>/dev/null); then
            for entry in "${iot_creds[@]}"; do
                IFS=':' read -r user pass desc <<< "$entry"
                local http_code
                http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --max-time 3 -u "${user}:${pass}" \
                    "http://${target}:${port}/" 2>/dev/null || echo "000")
                if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
                    log CRIT "  ├─ Default creds WORK: ${user}:${pass} (${desc}) on port $port"
                fi
            done
            break  # Only test on first open web port
        fi
    done

    # SSH default creds
    if (echo >/dev/tcp/"$target"/22 2>/dev/null); then
        log INFO "  ├─ SSH open — test for default IoT credentials manually"
        log INFO "  │  Common: root:root, admin:admin, pi:raspberry, ubnt:ubnt"
    fi
}

# ── UPnP Exposure ────────────────────────────────────────────

check_upnp_exposure() {
    local target="$1"
    echo -e "  ${CYAN}[UPnP]${NC} Checking UPnP/SSDP exposure"

    # UPnP HTTP description port
    if (echo >/dev/tcp/"$target"/49152 2>/dev/null) || \
       (echo >/dev/tcp/"$target"/1900 2>/dev/null); then
        log WARN "  ├─ UPnP service detected"
        echo -e "  ${RED}[!] UPnP can expose internal services to external networks.${NC}"
        echo -e "      ${RED}Disable UPnP on all OT/IoT devices.${NC}"
    fi

    if command -v nmap &>/dev/null; then
        local upnp_result
        upnp_result=$(nmap -sU -p 1900 --script upnp-info "$target" 2>/dev/null)
        if echo "$upnp_result" | grep -qi "upnp"; then
            log CRIT "  ├─ UPnP SSDP responding"
            echo "$upnp_result" | grep -E "^\|" | while read -r line; do
                log INFO "  │  $line"
            done
        fi
    fi
}

# ── Firmware Update Channels ─────────────────────────────────

check_iot_update_channels() {
    local target="$1"
    echo -e "  ${CYAN}[Updates]${NC} Checking firmware update security"

    # Check for HTTP (non-TLS) update endpoints
    if (echo >/dev/tcp/"$target"/80 2>/dev/null); then
        local update_paths=("/update" "/upgrade" "/firmware" "/ota" "/fwupdate" "/cgi-bin/firmware")
        for path in "${update_paths[@]}"; do
            local code
            code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://${target}${path}" 2>/dev/null || echo "000")
            if [[ "$code" != "000" ]] && [[ "$code" != "404" ]]; then
                log WARN "  ├─ Update endpoint ${path} accessible over HTTP (unencrypted)"
                echo -e "  ${RED}[!] Firmware updates over HTTP can be MITM'd.${NC}"
            fi
        done
    fi

    echo -e "  ${RED}[!] RECOMMENDATIONS:${NC}"
    echo -e "      • Enforce HTTPS for all firmware updates"
    echo -e "      • Validate firmware signatures before flashing"
    echo -e "      • Maintain firmware inventory and version tracking"
    echo -e "      • Subscribe to vendor security advisories"
}
