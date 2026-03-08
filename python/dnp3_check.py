#!/usr/bin/env python3
"""
OTAUD — DNP3 Protocol Security Checker
Checks DNP3 outstation exposure and Secure Authentication status.
Author: Ali AlEnezi (SiteQ8)
"""

import argparse
import socket
import struct
import sys
import json
from datetime import datetime


class DNP3Checker:
    """DNP3 (Distributed Network Protocol 3) security assessment."""

    DNP3_PORT = 20000
    START_BYTES = b'\x05\x64'

    def __init__(self, target, port=20000, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.findings = []

    def check_connectivity(self):
        print(f"\n[*] Checking DNP3 connectivity: {self.target}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            print(f"  [+] DNP3 port {self.port} is OPEN")
            self.findings.append({"severity": "HIGH", "check": "Connectivity",
                                  "detail": f"DNP3 port {self.port} accessible"})
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Cannot connect: {e}")
            return False

    def send_link_layer_request(self, src=3, dst=1):
        """Send a DNP3 Data Link Layer frame (read request)."""
        print(f"\n[*] Sending DNP3 link-layer request (src={src}, dst={dst})")
        # DNP3 Data Link Layer: Start(2) + Length(1) + Control(1) + Dst(2) + Src(2) + CRC(2)
        length = 5  # Minimum data link layer
        control = 0xC0  # DIR=1, PRM=1, FCV=0, FCB=0, FC=0 (Reset Link States)
        frame = struct.pack('<2sBBHH', self.START_BYTES, length, control, dst, src)

        # Calculate CRC-16 (DNP3 uses a specific CRC)
        crc = self._calc_crc(frame[0:8])
        frame += struct.pack('<H', crc)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(frame)
            response = sock.recv(1024)
            sock.close()

            if response and len(response) >= 10:
                if response[0:2] == self.START_BYTES:
                    print("  [+] DNP3 link-layer response received")
                    resp_ctrl = response[3]
                    resp_dst = struct.unpack('<H', response[4:6])[0]
                    resp_src = struct.unpack('<H', response[6:8])[0]
                    print(f"      Control: 0x{resp_ctrl:02X}, Dst: {resp_dst}, Src: {resp_src}")
                    self.findings.append({
                        "severity": "HIGH",
                        "check": "Link Layer Response",
                        "detail": f"Outstation responded (address {resp_src}→{resp_dst})"
                    })
                    return response
                else:
                    print("  [~] Non-DNP3 response received")
            else:
                print("  [-] No valid response")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Error: {e}")
        return None

    def check_broadcast_response(self):
        """Check if outstation responds to broadcast address."""
        print("\n[*] Checking broadcast address response (dst=65535)")
        resp = self.send_link_layer_request(src=3, dst=65535)
        if resp:
            self.findings.append({
                "severity": "CRITICAL",
                "check": "Broadcast Response",
                "detail": "Outstation responds to broadcast address — allows enumeration"
            })

    def enumerate_addresses(self):
        """Try common DNP3 outstation addresses."""
        print("\n[*] Enumerating DNP3 outstation addresses")
        found = []
        for addr in [1, 2, 3, 4, 5, 10, 20, 100, 200]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, self.port))

                length = 5
                control = 0xC0
                frame = struct.pack('<2sBBHH', self.START_BYTES, length, control, addr, 3)
                crc = self._calc_crc(frame[0:8])
                frame += struct.pack('<H', crc)

                sock.send(frame)
                resp = sock.recv(256)
                sock.close()

                if resp and resp[0:2] == self.START_BYTES:
                    print(f"  [+] Address {addr}: RESPONDING")
                    found.append(addr)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        if found:
            self.findings.append({
                "severity": "HIGH",
                "check": "Address Enumeration",
                "detail": f"Responding addresses: {found}"
            })
        return found

    def check_secure_authentication(self):
        """Check indicators of DNP3 Secure Authentication (SA)."""
        print("\n[*] Checking for Secure Authentication (SA) indicators")
        # SA v5 uses aggressive mode challenge-response
        # Without SA, link-layer requests succeed without any auth
        resp = self.send_link_layer_request(src=999, dst=1)
        if resp:
            print("  [!] Outstation accepted request from arbitrary source address")
            print("  [!] This indicates Secure Authentication is likely NOT enabled")
            self.findings.append({
                "severity": "CRITICAL",
                "check": "Secure Authentication",
                "detail": "No authentication required — SA v5 likely not enabled"
            })
        else:
            print("  [~] No response — SA may be active or address mismatch")

    def _calc_crc(self, data):
        """Calculate DNP3 CRC-16."""
        crc_table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
            crc_table.append(crc)

        crc = 0xFFFF
        for byte in data:
            crc = (crc >> 8) ^ crc_table[(crc ^ byte) & 0xFF]
        return crc ^ 0xFFFF

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  DNP3 SECURITY AUDIT REPORT")
        print(f"  Target: {self.target}:{self.port}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        for f in self.findings:
            sev = f["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "INFO": "🔵"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] {f['check']}: {f['detail']}")

        print("\n  RECOMMENDATIONS:")
        print("  1. Enable DNP3 Secure Authentication v5 (SA)")
        print("  2. Configure outstation to only accept known master addresses")
        print("  3. Deploy DNP3-aware IDS (e.g., Suricata with DNP3 parser)")
        print("  4. Encrypt DNP3 traffic using TLS/VPN tunnels")
        print("  5. Monitor for unsolicited response flooding")
        print("=" * 60)
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="OTAUD DNP3 Security Checker")
    parser.add_argument("--target", "-t", required=True, help="Target IP")
    parser.add_argument("--port", "-p", type=int, default=20000, help="DNP3 port")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    checker = DNP3Checker(args.target, args.port, args.timeout)
    if not checker.check_connectivity():
        sys.exit(1)

    checker.enumerate_addresses()
    checker.check_broadcast_response()
    checker.check_secure_authentication()
    findings = checker.generate_report()

    if args.json:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
