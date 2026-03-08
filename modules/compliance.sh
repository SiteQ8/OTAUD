#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OTAUD Module: Compliance Checker
# Validates OT environment against ICS security standards
# Supports: IEC 62443, NIST SP 800-82, NERC CIP, ISO 27001
# ═══════════════════════════════════════════════════════════════

run_compliance() {
    local target="${1:?Usage: run_compliance <target> [standard]}"
    local standard="${2:-$COMPLIANCE_STD}"
    log INFO "Compliance Check — Target: $target | Standard: $standard"

    # Run baseline technical checks
    run_baseline_checks "$target"

    # Standard-specific checks
    case "$standard" in
        iec62443)    check_iec62443 "$target" ;;
        nist80082)   check_nist_80082 "$target" ;;
        nerccip)     check_nerc_cip "$target" ;;
        iso27001)    check_iso27001 "$target" ;;
        all)
            check_iec62443 "$target"
            check_nist_80082 "$target"
            check_nerc_cip "$target"
            check_iso27001 "$target"
            ;;
        *)
            log ERROR "Unknown standard: $standard"
            log INFO "Supported: iec62443, nist80082, nerccip, iso27001, all"
            ;;
    esac

    log INFO "Compliance check completed."
}

# ── Baseline Technical Checks ─────────────────────────────────

run_baseline_checks() {
    local target="$1"
    echo -e "  ${CYAN}[Baseline]${NC} Running baseline technical compliance checks"

    local score=0
    local total=0
    local findings=()

    # 1. Encryption in transit
    ((total++))
    if (echo >/dev/tcp/"$target"/443 2>/dev/null) || (echo >/dev/tcp/"$target"/8443 2>/dev/null); then
        ((score++))
        log INFO "  ├─ [PASS] HTTPS/TLS endpoint available"
    else
        findings+=("No TLS endpoint detected — data in transit may be unencrypted")
        log WARN "  ├─ [FAIL] No HTTPS/TLS endpoint found"
    fi

    # 2. No Telnet
    ((total++))
    if ! (echo >/dev/tcp/"$target"/23 2>/dev/null); then
        ((score++))
        log INFO "  ├─ [PASS] Telnet disabled"
    else
        findings+=("Telnet (port 23) is open — unencrypted remote access")
        log CRIT "  ├─ [FAIL] Telnet is enabled"
    fi

    # 3. No FTP
    ((total++))
    if ! (echo >/dev/tcp/"$target"/21 2>/dev/null); then
        ((score++))
        log INFO "  ├─ [PASS] FTP disabled"
    else
        findings+=("FTP (port 21) is open — unencrypted file transfer")
        log WARN "  ├─ [FAIL] FTP is enabled"
    fi

    # 4. SSH available (as secure alternative)
    ((total++))
    if (echo >/dev/tcp/"$target"/22 2>/dev/null); then
        ((score++))
        log INFO "  ├─ [PASS] SSH available for secure remote access"
    else
        log INFO "  ├─ [INFO] SSH not detected (may not be applicable)"
    fi

    # 5. SNMP default community
    ((total++))
    if command -v snmpwalk &>/dev/null; then
        local snmp_pub
        snmp_pub=$(timeout 3 snmpwalk -v2c -c public "$target" 1.3.6.1.2.1.1.1 2>/dev/null | head -1 || true)
        if [[ -z "$snmp_pub" ]]; then
            ((score++))
            log INFO "  ├─ [PASS] SNMP 'public' community not accessible"
        else
            findings+=("SNMP default community 'public' is accessible")
            log CRIT "  ├─ [FAIL] SNMP 'public' community string works"
        fi
    else
        log INFO "  ├─ [SKIP] snmpwalk not available"
    fi

    # 6. No exposed industrial protocols without auth
    ((total++))
    local exposed_proto=0
    for port in 502 20000 102 44818 9600; do
        (echo >/dev/tcp/"$target"/"$port" 2>/dev/null) && ((exposed_proto++))
    done
    if [[ $exposed_proto -eq 0 ]]; then
        ((score++))
        log INFO "  ├─ [PASS] No unauthenticated industrial protocols exposed"
    else
        findings+=("$exposed_proto industrial protocol ports open without authentication")
        log WARN "  ├─ [FAIL] $exposed_proto industrial protocol(s) exposed"
    fi

    # 7. Web security headers
    ((total++))
    if (echo >/dev/tcp/"$target"/80 2>/dev/null) || (echo >/dev/tcp/"$target"/443 2>/dev/null); then
        local port=80
        (echo >/dev/tcp/"$target"/443 2>/dev/null) && port=443
        local headers
        headers=$(curl -skI --max-time 5 "http://${target}:${port}/" 2>/dev/null || true)
        local missing=0
        echo "$headers" | grep -qi "X-Frame-Options" || ((missing++))
        echo "$headers" | grep -qi "Content-Security-Policy" || ((missing++))
        echo "$headers" | grep -qi "X-Content-Type-Options" || ((missing++))
        if [[ $missing -eq 0 ]]; then
            ((score++))
            log INFO "  ├─ [PASS] Security headers present"
        else
            findings+=("$missing security headers missing on web interface")
            log WARN "  ├─ [FAIL] $missing security headers missing"
        fi
    else
        log INFO "  ├─ [SKIP] No web interface for header check"
    fi

    # Score Summary
    separator
    local pct=0
    [[ $total -gt 0 ]] && pct=$((score * 100 / total))
    echo -e "  ${BOLD}Baseline Score: ${score}/${total} (${pct}%)${NC}"
    if [[ $pct -ge 80 ]]; then
        echo -e "  ${GREEN}Rating: GOOD${NC}"
    elif [[ $pct -ge 50 ]]; then
        echo -e "  ${YELLOW}Rating: NEEDS IMPROVEMENT${NC}"
    else
        echo -e "  ${RED}Rating: CRITICAL — immediate action required${NC}"
    fi
    separator
}

# ── IEC 62443 ─────────────────────────────────────────────────

check_iec62443() {
    local target="$1"
    echo -e "\n  ${MAGENTA}[IEC 62443]${NC} Industrial Automation & Control Systems Security"

    echo -e "  ${BOLD}Checking Security Levels (SL) requirements:${NC}"

    # FR 1: Identification and Authentication
    echo -e "  ${CYAN}FR 1: Identification & Authentication${NC}"
    log INFO "  ├─ SR 1.1: Human user identification"
    if (echo >/dev/tcp/"$target"/80 2>/dev/null); then
        local login_page
        login_page=$(curl -sk --max-time 5 "http://${target}/" 2>/dev/null | head -100 || true)
        if echo "$login_page" | grep -qi "login\|password\|authenticate\|sign.in"; then
            log INFO "  │  Login page detected — verify strong password policy"
        else
            log WARN "  │  No login page detected — check authentication requirements"
        fi
    fi

    # FR 2: Use Control
    echo -e "  ${CYAN}FR 2: Use Control${NC}"
    log INFO "  ├─ SR 2.1: Authorization enforcement — verify RBAC implementation"
    log INFO "  ├─ SR 2.2: Wireless use control — check for unauthorized Wi-Fi APs"

    # FR 3: System Integrity
    echo -e "  ${CYAN}FR 3: System Integrity${NC}"
    log INFO "  ├─ SR 3.1: Communication integrity — verify TLS/encryption"
    log INFO "  ├─ SR 3.2: Malicious code protection — check endpoint security"

    # FR 4: Data Confidentiality
    echo -e "  ${CYAN}FR 4: Data Confidentiality${NC}"
    log INFO "  ├─ SR 4.1: Information confidentiality — verify encryption at rest"

    # FR 5: Restricted Data Flow
    echo -e "  ${CYAN}FR 5: Restricted Data Flow${NC}"
    log INFO "  ├─ SR 5.1: Network segmentation — verify zone/conduit model"

    # FR 6: Timely Response to Events
    echo -e "  ${CYAN}FR 6: Timely Response to Events${NC}"
    log INFO "  ├─ SR 6.1: Audit log accessibility — verify logging is enabled"
    log INFO "  ├─ SR 6.2: Continuous monitoring — check for IDS/IPS"

    # FR 7: Resource Availability
    echo -e "  ${CYAN}FR 7: Resource Availability${NC}"
    log INFO "  ├─ SR 7.1: DoS protection — verify resource limits"
    log INFO "  ├─ SR 7.2: Resource management — check for redundancy"
}

# ── NIST SP 800-82 ────────────────────────────────────────────

check_nist_80082() {
    local target="$1"
    echo -e "\n  ${MAGENTA}[NIST 800-82]${NC} Guide to ICS Security"

    echo -e "  ${BOLD}Checking key NIST SP 800-82 Rev 3 controls:${NC}"

    echo -e "  ${CYAN}Section 5: ICS Risk Management${NC}"
    log INFO "  ├─ 5.1: Asset inventory — verify all OT assets are cataloged"
    log INFO "  ├─ 5.2: Risk assessment — confirm threat modeling performed"

    echo -e "  ${CYAN}Section 6: ICS Security Architecture${NC}"
    log INFO "  ├─ 6.1: Network segmentation (DMZ between IT/OT)"

    # Technical validation
    local it_ports_open=0
    for port in 445 3389 389; do
        (echo >/dev/tcp/"$target"/"$port" 2>/dev/null) && ((it_ports_open++))
    done
    if [[ $it_ports_open -gt 0 ]]; then
        log WARN "  │  $it_ports_open IT-centric ports reachable from OT — segmentation concern"
    else
        log INFO "  │  IT-centric ports not reachable — good segmentation indicator"
    fi

    log INFO "  ├─ 6.2: Defense-in-depth strategy"
    log INFO "  ├─ 6.3: Recommended firewall rules for ICS protocols"

    echo -e "  ${CYAN}Section 6.2: ICS-Specific Recommendations${NC}"
    log INFO "  ├─ Restrict physical access to ICS components"
    log INFO "  ├─ Disable unnecessary services and ports"
    log INFO "  ├─ Apply patches following vendor-approved procedures"
    log INFO "  ├─ Implement role-based access control (RBAC)"
}

# ── NERC CIP ─────────────────────────────────────────────────

check_nerc_cip() {
    local target="$1"
    echo -e "\n  ${MAGENTA}[NERC CIP]${NC} Critical Infrastructure Protection (Electric Sector)"

    echo -e "  ${BOLD}Checking NERC CIP v5/v7 requirements:${NC}"

    echo -e "  ${CYAN}CIP-002: BES Cyber System Categorization${NC}"
    log INFO "  ├─ Verify asset is categorized (High/Medium/Low impact)"

    echo -e "  ${CYAN}CIP-005: Electronic Security Perimeters${NC}"
    log INFO "  ├─ R1: Define Electronic Security Perimeter (ESP)"
    log INFO "  ├─ R2: Interactive remote access requires multi-factor auth"

    # Check for interactive remote access without MFA indicators
    local rdp_open=0
    (echo >/dev/tcp/"$target"/3389 2>/dev/null) && rdp_open=1
    local vnc_open=0
    (echo >/dev/tcp/"$target"/5900 2>/dev/null) && vnc_open=1

    if [[ $rdp_open -eq 1 ]] || [[ $vnc_open -eq 1 ]]; then
        log WARN "  │  Remote desktop access detected — ensure MFA is enforced"
    fi

    echo -e "  ${CYAN}CIP-007: System Security Management${NC}"
    log INFO "  ├─ R1: Ports & Services — disable unnecessary ports"
    log INFO "  ├─ R2: Security patch management process"
    log INFO "  ├─ R3: Malicious code prevention"
    log INFO "  ├─ R4: Security event monitoring"
    log INFO "  ├─ R5: System access control — no shared accounts"

    echo -e "  ${CYAN}CIP-010: Configuration Change Management${NC}"
    log INFO "  ├─ R1: Maintain baseline configuration"
    log INFO "  ├─ R2: Configuration monitoring (30-day cycle)"
    log INFO "  ├─ R3: Vulnerability assessments (15-month cycle)"

    echo -e "  ${CYAN}CIP-011: Information Protection${NC}"
    log INFO "  ├─ R1: BES Cyber System Information classification"
    log INFO "  ├─ R2: Media sanitization procedures"
}

# ── ISO 27001 (OT context) ───────────────────────────────────

check_iso27001() {
    local target="$1"
    echo -e "\n  ${MAGENTA}[ISO 27001]${NC} Information Security Management (OT Context)"

    echo -e "  ${BOLD}Checking Annex A controls relevant to OT:${NC}"

    echo -e "  ${CYAN}A.5: Information Security Policies${NC}"
    log INFO "  ├─ Verify OT-specific security policy exists"

    echo -e "  ${CYAN}A.8: Asset Management${NC}"
    log INFO "  ├─ A.8.1: OT asset inventory completeness"
    log INFO "  ├─ A.8.2: Information classification for OT data"

    echo -e "  ${CYAN}A.9: Access Control${NC}"
    log INFO "  ├─ A.9.1: Access control policy for OT systems"
    log INFO "  ├─ A.9.2: User access management"
    log INFO "  ├─ A.9.4: System and application access control"

    echo -e "  ${CYAN}A.12: Operations Security${NC}"
    log INFO "  ├─ A.12.1: Operational procedures and responsibilities"
    log INFO "  ├─ A.12.2: Protection from malware"
    log INFO "  ├─ A.12.4: Logging and monitoring"
    log INFO "  ├─ A.12.6: Technical vulnerability management"

    echo -e "  ${CYAN}A.13: Communications Security${NC}"
    log INFO "  ├─ A.13.1: Network segmentation (IT/OT separation)"
    log INFO "  ├─ A.13.2: Secure information transfer"

    echo -e "  ${CYAN}A.14: System Development Security${NC}"
    log INFO "  ├─ A.14.2: Secure development policy for ICS software"

    echo -e "  ${CYAN}A.17: Business Continuity${NC}"
    log INFO "  ├─ A.17.1: OT-specific disaster recovery plan"
    log INFO "  ├─ A.17.2: Availability of critical OT systems"
}
