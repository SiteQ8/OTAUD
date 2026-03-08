#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  OTAUD - OT/ICS/IoT Security Auditing Toolkit                      ║
# ║  Author : Ali AlEnezi (SiteQ8)                                      ║
# ║  License: MIT                                                       ║
# ║  Repo   : https://github.com/SiteQ8/OTAUD                          ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# A comprehensive, all-in-one security auditing framework for
# Industrial Control Systems (ICS), IoT devices, and Operational
# Technology (OT) environments.

set -euo pipefail
IFS=$'\n\t'

# ── Globals ───────────────────────────────────────────────────────────
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"
PYTHON_DIR="${SCRIPT_DIR}/python"
CONFIGS_DIR="${SCRIPT_DIR}/configs"
REPORT_DIR="${SCRIPT_DIR}/reports"
LOG_FILE="${REPORT_DIR}/otaud_$(date +%Y%m%d_%H%M%S).log"
TIMESTAMP="$(date +%Y-%m-%d\ %H:%M:%S)"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# Defaults
TARGET=""
SCAN_TYPE="full"
OUTPUT_FORMAT="html"
VERBOSE=0
DRY_RUN=0
COMPLIANCE_STD="iec62443"
THREADS=10

# ── Utility Functions ─────────────────────────────────────────────────

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date +%H:%M:%S)"
    case "$level" in
        INFO)  echo -e "${CYAN}[${ts}]${NC} ${GREEN}[INFO]${NC}  $msg" ;;
        WARN)  echo -e "${CYAN}[${ts}]${NC} ${YELLOW}[WARN]${NC}  $msg" ;;
        ERROR) echo -e "${CYAN}[${ts}]${NC} ${RED}[ERROR]${NC} $msg" ;;
        DEBUG) [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[${ts}]${NC} ${DIM}[DEBUG]${NC} $msg" ;;
        CRIT)  echo -e "${CYAN}[${ts}]${NC} ${RED}${BOLD}[CRIT]${NC}  $msg" ;;
    esac
    echo "[${ts}] [${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'

   ▄██████▄      ███        ▄████████ ███    █▄  ████████▄
  ███    ███  ▀█████████▄  ███    ███ ███    ███ ███   ▀███
  ███    ███     ▀███▀▀██  ███    ███ ███    ███ ███    ███
  ███    ███      ███   ▀  ███    ███ ███    ███ ███    ███
  ███    ███      ███    ▀███████████ ███    ███ ███    ███
  ███    ███      ███      ███    ███ ███    ███ ███    ███
  ███    ███      ███      ███    ███ ███    ███ ███   ▄███
   ▀██████▀      ▄████▀    ███    █▀  ████████▀  ████████▀

BANNER
    echo -e "${NC}"
    echo -e "  ${BOLD}OT / ICS / IoT Security Auditing Toolkit${NC}"
    echo -e "  ${DIM}Version ${VERSION} | by Ali AlEnezi (SiteQ8)${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────${NC}"
    echo ""
}

separator() {
    echo -e "${DIM}──────────────────────────────────────────────────────────${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log WARN "Some modules require root privileges for full functionality."
        log WARN "Consider running with: sudo $0 $*"
    fi
}

check_dependencies() {
    log INFO "Checking dependencies..."
    local deps=(nmap curl wget python3 jq dig ss arp)
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log WARN "Missing optional dependencies: ${missing[*]}"
        log INFO "Install with: sudo apt install ${missing[*]}"
    else
        log INFO "All dependencies satisfied."
    fi
}

# ── Module Loader ─────────────────────────────────────────────────────

load_module() {
    local module="$1"
    local module_path="${MODULES_DIR}/${module}.sh"
    if [[ -f "$module_path" ]]; then
        source "$module_path"
        log DEBUG "Loaded module: $module"
    else
        log ERROR "Module not found: $module_path"
        return 1
    fi
}

run_module() {
    local module="$1"; shift
    separator
    echo -e "${MAGENTA}${BOLD}▶ Running Module: ${module}${NC}"
    separator
    load_module "$module"
    if declare -f "run_${module}" &>/dev/null; then
        "run_${module}" "$@"
    else
        log ERROR "Module '$module' does not export run_${module}()"
    fi
}

# ── Main Scan Orchestrator ────────────────────────────────────────────

run_full_audit() {
    local target="$1"
    log INFO "Starting FULL OT/ICS/IoT audit on target: ${BOLD}${target}${NC}"
    echo ""

    local modules=(
        network_scan
        protocol_audit
        config_audit
        plc_check
        scada_audit
        iot_scan
        firmware_check
        compliance
    )

    local total=${#modules[@]}
    local current=0

    for mod in "${modules[@]}"; do
        ((current++))
        echo -e "\n${BLUE}[${current}/${total}]${NC} ${BOLD}${mod}${NC}"
        if [[ -f "${MODULES_DIR}/${mod}.sh" ]]; then
            run_module "$mod" "$target"
        else
            log WARN "Skipping ${mod} — module file not found"
        fi
    done

    separator
    log INFO "Full audit completed. Generating report..."
    generate_report "$target"
}

run_quick_scan() {
    local target="$1"
    log INFO "Starting QUICK scan on target: ${BOLD}${target}${NC}"
    local quick_modules=(network_scan protocol_audit iot_scan)
    for mod in "${quick_modules[@]}"; do
        run_module "$mod" "$target"
    done
    generate_report "$target"
}

run_compliance_only() {
    local target="$1"
    log INFO "Running compliance check (${COMPLIANCE_STD}) on: ${BOLD}${target}${NC}"
    run_module compliance "$target" "$COMPLIANCE_STD"
    generate_report "$target"
}

# ── Report Generator ─────────────────────────────────────────────────

generate_report() {
    local target="$1"
    local report_file="${REPORT_DIR}/otaud_report_$(date +%Y%m%d_%H%M%S)"

    if command -v python3 &>/dev/null && [[ -f "${PYTHON_DIR}/report_gen.py" ]]; then
        python3 "${PYTHON_DIR}/report_gen.py" \
            --log "$LOG_FILE" \
            --target "$target" \
            --format "$OUTPUT_FORMAT" \
            --output "${report_file}.${OUTPUT_FORMAT}" \
            --standard "$COMPLIANCE_STD" 2>/dev/null && \
        log INFO "Report saved: ${report_file}.${OUTPUT_FORMAT}" || \
        log WARN "Python report generator failed, falling back to text"
    fi

    # Always produce a text summary
    {
        echo "═══════════════════════════════════════════════════════"
        echo "  OTAUD Audit Report — $(date)"
        echo "  Target: $target"
        echo "  Scan Type: $SCAN_TYPE"
        echo "  Compliance Standard: $COMPLIANCE_STD"
        echo "═══════════════════════════════════════════════════════"
        echo ""
        cat "$LOG_FILE" 2>/dev/null || echo "(no log data)"
    } > "${report_file}.txt"

    log INFO "Text report saved: ${report_file}.txt"
}

# ── Interactive Menu ──────────────────────────────────────────────────

interactive_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}┌─────────────────────────────────────┐${NC}"
        echo -e "${BOLD}│       OTAUD — Main Menu             │${NC}"
        echo -e "${BOLD}├─────────────────────────────────────┤${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}1)${NC} Full OT/ICS/IoT Audit           ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}2)${NC} Quick Network Scan              ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}3)${NC} Protocol Analysis               ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}4)${NC} PLC / HMI Security Check        ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}5)${NC} SCADA System Audit              ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}6)${NC} IoT Device Discovery            ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}7)${NC} Firmware Analysis               ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}8)${NC} Configuration Audit             ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${GREEN}9)${NC} Compliance Check                ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${CYAN}10)${NC} Python Advanced Modules         ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${YELLOW}11)${NC} Generate Report                ${BOLD}│${NC}"
        echo -e "${BOLD}│${NC}  ${RED}0)${NC}  Exit                           ${BOLD}│${NC}"
        echo -e "${BOLD}└─────────────────────────────────────┘${NC}"
        echo ""
        read -rp "$(echo -e "${CYAN}Select option [0-11]: ${NC}")" choice

        case "$choice" in
            1)
                read -rp "Target IP/Range: " t
                run_full_audit "$t"
                ;;
            2)
                read -rp "Target IP/Range: " t
                run_module network_scan "$t"
                ;;
            3)
                read -rp "Target IP: " t
                run_module protocol_audit "$t"
                ;;
            4)
                read -rp "Target IP: " t
                run_module plc_check "$t"
                ;;
            5)
                read -rp "Target IP: " t
                run_module scada_audit "$t"
                ;;
            6)
                read -rp "Target IP/Range: " t
                run_module iot_scan "$t"
                ;;
            7)
                read -rp "Target IP or firmware file path: " t
                run_module firmware_check "$t"
                ;;
            8)
                read -rp "Target IP or config file: " t
                run_module config_audit "$t"
                ;;
            9)
                echo -e "Standards: ${GREEN}iec62443${NC} | ${GREEN}nist80082${NC} | ${GREEN}nerccip${NC} | ${GREEN}iso27001${NC}"
                read -rp "Standard [iec62443]: " std
                COMPLIANCE_STD="${std:-iec62443}"
                read -rp "Target IP/Range: " t
                run_compliance_only "$t"
                ;;
            10)
                python_modules_menu
                ;;
            11)
                read -rp "Target (for report header): " t
                generate_report "${t:-unknown}"
                ;;
            0)
                echo -e "${GREEN}Exiting OTAUD. Stay secure!${NC}"
                exit 0
                ;;
            *)
                log WARN "Invalid option: $choice"
                ;;
        esac
    done
}

python_modules_menu() {
    echo ""
    echo -e "${BOLD}Python Advanced Modules${NC}"
    echo -e "  ${GREEN}a)${NC} Modbus TCP Auditor"
    echo -e "  ${GREEN}b)${NC} DNP3 Protocol Checker"
    echo -e "  ${GREEN}c)${NC} MQTT Broker Audit"
    echo -e "  ${GREEN}d)${NC} OPC-UA Scanner"
    echo -e "  ${GREEN}e)${NC} CVE Lookup for OT Devices"
    echo -e "  ${GREEN}f)${NC} Back"
    echo ""
    read -rp "$(echo -e "${CYAN}Select [a-f]: ${NC}")" py_choice

    case "$py_choice" in
        a) read -rp "Modbus target IP: " t
           python3 "${PYTHON_DIR}/modbus_audit.py" --target "$t" ;;
        b) read -rp "DNP3 target IP: " t
           python3 "${PYTHON_DIR}/dnp3_check.py" --target "$t" ;;
        c) read -rp "MQTT broker IP: " t
           python3 "${PYTHON_DIR}/mqtt_audit.py" --target "$t" ;;
        d) read -rp "OPC-UA server URL: " t
           python3 "${PYTHON_DIR}/opcua_scan.py" --target "$t" ;;
        e) read -rp "Device/vendor keyword: " t
           python3 "${PYTHON_DIR}/cve_lookup.py" --query "$t" ;;
        f) return ;;
        *) log WARN "Invalid option" ;;
    esac
}

# ── Usage / Help ──────────────────────────────────────────────────────

usage() {
    cat << EOF
${BOLD}OTAUD — OT/ICS/IoT Security Auditing Toolkit v${VERSION}${NC}
${DIM}Author: Ali AlEnezi (SiteQ8)${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS] -t <target>
    $0 --interactive

${BOLD}OPTIONS:${NC}
    -t, --target <ip/range>     Target IP address or CIDR range
    -s, --scan <type>           Scan type: full | quick | compliance
    -m, --module <name>         Run a specific module only
    -o, --output <format>       Output: html | json | txt | pdf (default: html)
    -c, --compliance <std>      Standard: iec62443 | nist80082 | nerccip | iso27001
    -T, --threads <n>           Thread count (default: 10)
    -v, --verbose               Enable verbose/debug output
    -n, --dry-run               Show what would run without executing
    -i, --interactive           Launch interactive menu
    -h, --help                  Show this help message
    -V, --version               Show version

${BOLD}MODULES:${NC}
    network_scan       Network discovery, host enumeration, port scanning
    protocol_audit     Industrial protocol analysis (Modbus, DNP3, S7, EtherNet/IP)
    config_audit       Configuration & hardening checks
    plc_check          PLC/HMI/RTU security assessment
    scada_audit        SCADA system security audit
    iot_scan           IoT device discovery & vulnerability scan
    firmware_check     Firmware version checks & known CVE matching
    compliance         Compliance assessment against ICS standards

${BOLD}EXAMPLES:${NC}
    $0 -t 192.168.1.0/24 -s full
    $0 -t 10.0.0.50 -m protocol_audit -v
    $0 -t 172.16.0.0/16 -s compliance -c iec62443
    $0 --interactive

EOF
}

# ── Argument Parser ───────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)      TARGET="$2"; shift 2 ;;
            -s|--scan)        SCAN_TYPE="$2"; shift 2 ;;
            -m|--module)      SCAN_TYPE="module:$2"; shift 2 ;;
            -o|--output)      OUTPUT_FORMAT="$2"; shift 2 ;;
            -c|--compliance)  COMPLIANCE_STD="$2"; shift 2 ;;
            -T|--threads)     THREADS="$2"; shift 2 ;;
            -v|--verbose)     VERBOSE=1; shift ;;
            -n|--dry-run)     DRY_RUN=1; shift ;;
            -i|--interactive) SCAN_TYPE="interactive"; shift ;;
            -h|--help)        usage; exit 0 ;;
            -V|--version)     echo "OTAUD v${VERSION}"; exit 0 ;;
            *)                log ERROR "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# ── Entry Point ───────────────────────────────────────────────────────

main() {
    mkdir -p "$REPORT_DIR"
    banner
    parse_args "$@"
    check_root "$@"
    check_dependencies

    export TARGET SCAN_TYPE OUTPUT_FORMAT VERBOSE DRY_RUN COMPLIANCE_STD THREADS
    export MODULES_DIR PYTHON_DIR CONFIGS_DIR REPORT_DIR LOG_FILE

    if [[ "$SCAN_TYPE" == "interactive" ]]; then
        interactive_menu
        return
    fi

    if [[ -z "$TARGET" ]]; then
        log ERROR "No target specified. Use -t <target> or --interactive"
        usage
        exit 1
    fi

    case "$SCAN_TYPE" in
        full)         run_full_audit "$TARGET" ;;
        quick)        run_quick_scan "$TARGET" ;;
        compliance)   run_compliance_only "$TARGET" ;;
        module:*)     run_module "${SCAN_TYPE#module:}" "$TARGET" ;;
        *)            log ERROR "Unknown scan type: $SCAN_TYPE"; exit 1 ;;
    esac

    echo ""
    log INFO "Audit complete. Log: ${LOG_FILE}"
    log INFO "Reports directory: ${REPORT_DIR}"
}

main "$@"
