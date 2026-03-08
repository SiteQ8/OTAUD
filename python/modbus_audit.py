#!/usr/bin/env python3
"""
OTAUD — Modbus TCP Security Auditor
Performs deep inspection of Modbus TCP devices for misconfigurations,
unauthorized access, and information disclosure.
Author: Ali AlEnezi (SiteQ8)
"""

import argparse
import socket
import struct
import sys
import json
from datetime import datetime

# Modbus function codes
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_READ_EXCEPTION_STATUS = 0x07
FC_DIAGNOSTICS = 0x08
FC_WRITE_MULTIPLE_COILS = 0x0F
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_REPORT_SERVER_ID = 0x11
FC_READ_DEVICE_ID = 0x2B

FUNCTION_CODE_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x2B: "Read Device Identification",
}


class ModbusAuditor:
    def __init__(self, target, port=502, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.transaction_id = 0
        self.findings = []

    def _build_mbap(self, unit_id, pdu):
        """Build Modbus Application Protocol header."""
        self.transaction_id += 1
        length = len(pdu) + 1  # PDU + unit_id
        return struct.pack('>HHHB', self.transaction_id, 0, length, unit_id) + pdu

    def _send_receive(self, packet):
        """Send a Modbus TCP packet and receive response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(packet)
            response = sock.recv(1024)
            sock.close()
            return response
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def check_connectivity(self):
        """Test basic Modbus TCP connectivity."""
        print(f"\n[*] Testing Modbus TCP connectivity to {self.target}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            print(f"  [+] Port {self.port} is OPEN")
            self.findings.append({
                "severity": "INFO",
                "check": "Connectivity",
                "detail": f"Modbus TCP port {self.port} is open"
            })
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Cannot connect: {e}")
            return False

    def enumerate_unit_ids(self):
        """Scan for responding Modbus unit IDs."""
        print("\n[*] Enumerating Modbus Unit IDs (slaves)")
        active_units = []
        test_ids = list(range(0, 11)) + [100, 200, 247, 255]

        for uid in test_ids:
            pdu = struct.pack('>BHH', FC_READ_HOLDING_REGISTERS, 0, 1)
            packet = self._build_mbap(uid, pdu)
            response = self._send_receive(packet)

            if response and len(response) > 7:
                error_code = response[7] if len(response) > 7 else 0
                if error_code < 0x80:  # Not an exception
                    print(f"  [+] Unit ID {uid}: RESPONDING")
                    active_units.append(uid)
                else:
                    exception = response[8] if len(response) > 8 else 0
                    print(f"  [~] Unit ID {uid}: Exception code {exception}")

        if active_units:
            self.findings.append({
                "severity": "HIGH",
                "check": "Unit ID Enumeration",
                "detail": f"Active unit IDs found: {active_units}"
            })
        return active_units

    def check_function_codes(self, unit_id=1):
        """Test which function codes are allowed."""
        print(f"\n[*] Testing allowed function codes on Unit ID {unit_id}")
        allowed = []

        test_codes = [
            (FC_READ_COILS, struct.pack('>HH', 0, 1)),
            (FC_READ_DISCRETE_INPUTS, struct.pack('>HH', 0, 1)),
            (FC_READ_HOLDING_REGISTERS, struct.pack('>HH', 0, 1)),
            (FC_READ_INPUT_REGISTERS, struct.pack('>HH', 0, 1)),
            (FC_READ_EXCEPTION_STATUS, b''),
            (FC_DIAGNOSTICS, struct.pack('>HH', 0, 0)),
            (FC_REPORT_SERVER_ID, b''),
            (FC_READ_DEVICE_ID, struct.pack('>BBB', 0x0E, 1, 0)),
        ]

        for fc, data in test_codes:
            pdu = struct.pack('>B', fc) + data
            packet = self._build_mbap(unit_id, pdu)
            response = self._send_receive(packet)

            name = FUNCTION_CODE_NAMES.get(fc, f"FC {fc:#04x}")
            if response and len(response) > 7:
                resp_fc = response[7]
                if resp_fc == fc:  # Success
                    print(f"  [+] {name} (0x{fc:02x}): ALLOWED")
                    allowed.append(name)
                elif resp_fc == (fc | 0x80):
                    exc = response[8] if len(response) > 8 else 0
                    print(f"  [-] {name} (0x{fc:02x}): Exception {exc}")
                else:
                    print(f"  [?] {name} (0x{fc:02x}): Unexpected response")
            else:
                print(f"  [-] {name} (0x{fc:02x}): No response")

        # Check WRITE function codes (read-only test — no actual write)
        write_codes = [
            (FC_WRITE_SINGLE_COIL, "Write Single Coil"),
            (FC_WRITE_SINGLE_REGISTER, "Write Single Register"),
            (FC_WRITE_MULTIPLE_COILS, "Write Multiple Coils"),
            (FC_WRITE_MULTIPLE_REGISTERS, "Write Multiple Registers"),
        ]
        write_allowed = []
        for fc, name in write_codes:
            # Send a read-like probe to see if FC is even recognized
            pdu = struct.pack('>B', fc) + b'\x00' * 4
            packet = self._build_mbap(unit_id, pdu)
            response = self._send_receive(packet)
            if response and len(response) > 7:
                resp_fc = response[7]
                if resp_fc != (fc | 0x80) or (len(response) > 8 and response[8] != 1):
                    # Function code recognized (not "Illegal Function")
                    print(f"  [!] {name} (0x{fc:02x}): RECOGNIZED (write capable)")
                    write_allowed.append(name)

        if write_allowed:
            self.findings.append({
                "severity": "CRITICAL",
                "check": "Write Functions",
                "detail": f"Write function codes accessible: {write_allowed}"
            })

        return allowed

    def read_device_identification(self, unit_id=1):
        """Attempt to read Modbus device identification (FC 0x2B)."""
        print(f"\n[*] Reading Device Identification (FC 0x2B) on Unit ID {unit_id}")
        pdu = struct.pack('>BBBB', FC_READ_DEVICE_ID, 0x0E, 0x01, 0x00)
        packet = self._build_mbap(unit_id, pdu)
        response = self._send_receive(packet)

        if response and len(response) > 10 and response[7] == FC_READ_DEVICE_ID:
            print("  [+] Device identification data received:")
            # Parse MEI response
            try:
                idx = 11  # Start of objects
                num_objects = response[10] if len(response) > 10 else 0
                for _ in range(num_objects):
                    if idx + 2 > len(response):
                        break
                    obj_id = response[idx]
                    obj_len = response[idx + 1]
                    obj_val = response[idx + 2:idx + 2 + obj_len].decode('ascii', errors='replace')
                    obj_names = {0: "VendorName", 1: "ProductCode", 2: "MajorMinorRevision"}
                    name = obj_names.get(obj_id, f"Object_{obj_id}")
                    print(f"      {name}: {obj_val}")
                    self.findings.append({
                        "severity": "INFO",
                        "check": "Device ID",
                        "detail": f"{name}: {obj_val}"
                    })
                    idx += 2 + obj_len
            except (IndexError, UnicodeDecodeError):
                print("  [~] Partial device identification data received")
        else:
            print("  [-] Device identification not available")

    def read_register_sample(self, unit_id=1):
        """Read a sample of holding registers to check data exposure."""
        print(f"\n[*] Sampling holding registers (information disclosure check)")
        register_ranges = [(0, 10), (100, 10), (1000, 10), (4000, 10)]

        for start, count in register_ranges:
            pdu = struct.pack('>BHH', FC_READ_HOLDING_REGISTERS, start, count)
            packet = self._build_mbap(unit_id, pdu)
            response = self._send_receive(packet)

            if response and len(response) > 9 and response[7] == FC_READ_HOLDING_REGISTERS:
                byte_count = response[8]
                if byte_count > 0:
                    values = []
                    for i in range(0, byte_count, 2):
                        if 9 + i + 1 < len(response):
                            val = struct.unpack('>H', response[9 + i:9 + i + 2])[0]
                            values.append(val)
                    print(f"  [+] Registers {start}-{start + count - 1}: {values}")
                    self.findings.append({
                        "severity": "HIGH",
                        "check": "Register Read",
                        "detail": f"Holding registers {start}-{start + count - 1} readable: {values}"
                    })

    def generate_report(self):
        """Generate audit findings report."""
        print("\n" + "=" * 60)
        print("  MODBUS TCP AUDIT REPORT")
        print(f"  Target: {self.target}:{self.port}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high = [f for f in self.findings if f["severity"] == "HIGH"]
        info = [f for f in self.findings if f["severity"] == "INFO"]

        print(f"\n  CRITICAL: {len(critical)}  |  HIGH: {len(high)}  |  INFO: {len(info)}")
        print("-" * 60)

        for finding in self.findings:
            sev = finding["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "INFO": "🔵"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] {finding['check']}: {finding['detail']}")

        print("\n  RECOMMENDATIONS:")
        print("  1. Deploy Modbus-aware firewall with function code filtering")
        print("  2. Implement network segmentation (Purdue model)")
        print("  3. Monitor all Modbus traffic with OT-specific IDS")
        print("  4. Disable unnecessary function codes at device level")
        print("  5. Restrict access by source IP whitelist")
        print("=" * 60)

        return self.findings


def main():
    parser = argparse.ArgumentParser(description="OTAUD Modbus TCP Auditor")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=502, help="Modbus TCP port (default: 502)")
    parser.add_argument("--unit-id", "-u", type=int, default=1, help="Modbus unit ID to test (default: 1)")
    parser.add_argument("--timeout", type=int, default=5, help="Socket timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    args = parser.parse_args()

    auditor = ModbusAuditor(args.target, args.port, args.timeout)

    if not auditor.check_connectivity():
        sys.exit(1)

    units = auditor.enumerate_unit_ids()
    uid = args.unit_id if args.unit_id in units else (units[0] if units else args.unit_id)

    auditor.check_function_codes(uid)
    auditor.read_device_identification(uid)
    auditor.read_register_sample(uid)

    findings = auditor.generate_report()

    if args.json:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
