#!/usr/bin/env python3
"""
OTAUD — MQTT Broker Security Auditor
Checks MQTT brokers for misconfigurations common in IoT/OT environments.
Author: Ali AlEnezi (SiteQ8)
"""

import argparse
import socket
import struct
import ssl
import sys
import json
from datetime import datetime


class MQTTAuditor:
    """MQTT (Message Queuing Telemetry Transport) security auditor."""

    MQTT_CONNECT = 0x10
    MQTT_CONNACK = 0x20
    MQTT_SUBSCRIBE = 0x82
    MQTT_SUBACK = 0x90

    def __init__(self, target, port=1883, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.findings = []

    def _build_connect(self, client_id="otaud_probe", username=None, password=None):
        """Build MQTT CONNECT packet."""
        # Variable header: Protocol Name + Level + Flags + Keep Alive
        var_header = struct.pack('>H', 4) + b'MQTT'  # Protocol name
        var_header += struct.pack('B', 4)  # Protocol level (MQTT 3.1.1)

        flags = 0x02  # Clean session
        if username:
            flags |= 0x80
        if password:
            flags |= 0x40

        var_header += struct.pack('B', flags)
        var_header += struct.pack('>H', 60)  # Keep alive (60s)

        # Payload: Client ID
        payload = struct.pack('>H', len(client_id)) + client_id.encode()
        if username:
            payload += struct.pack('>H', len(username)) + username.encode()
        if password:
            payload += struct.pack('>H', len(password)) + password.encode()

        remaining = var_header + payload
        packet = struct.pack('B', self.MQTT_CONNECT)
        packet += self._encode_remaining_length(len(remaining))
        packet += remaining
        return packet

    def _encode_remaining_length(self, length):
        encoded = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length <= 0:
                break
        return bytes(encoded)

    def _send_receive(self, packet, use_tls=False):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)
            sock.connect((self.target, self.port))
            sock.send(packet)
            response = sock.recv(1024)
            sock.close()
            return response
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
            return None

    def check_connectivity(self):
        print(f"\n[*] Checking MQTT broker: {self.target}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            print(f"  [+] MQTT port {self.port} is OPEN")
            if self.port == 1883:
                self.findings.append({
                    "severity": "HIGH",
                    "check": "Unencrypted Port",
                    "detail": "MQTT on port 1883 (plaintext) — use 8883 (TLS)"
                })
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Cannot connect: {e}")
            return False

    def check_anonymous_access(self):
        """Test if broker accepts connections without credentials."""
        print("\n[*] Testing anonymous access")
        use_tls = self.port in (8883, 8884)
        packet = self._build_connect(client_id="otaud_anon_test")
        response = self._send_receive(packet, use_tls=use_tls)

        if response and len(response) >= 4 and (response[0] & 0xF0) == self.MQTT_CONNACK:
            return_code = response[3]
            codes = {
                0: "Accepted (anonymous access ALLOWED)",
                1: "Refused (bad protocol version)",
                2: "Refused (identifier rejected)",
                3: "Refused (server unavailable)",
                4: "Refused (bad username/password)",
                5: "Refused (not authorized)",
            }
            msg = codes.get(return_code, f"Unknown code {return_code}")
            if return_code == 0:
                print(f"  [!] CONNACK: {msg}")
                self.findings.append({
                    "severity": "CRITICAL",
                    "check": "Anonymous Access",
                    "detail": "Broker accepts connections without authentication"
                })
                return True
            else:
                print(f"  [+] CONNACK: {msg}")
                if return_code in (4, 5):
                    self.findings.append({
                        "severity": "INFO",
                        "check": "Authentication",
                        "detail": "Broker requires credentials (good)"
                    })
                return False
        else:
            print("  [-] No valid CONNACK received")
            return False

    def check_default_credentials(self):
        """Test common default MQTT credentials."""
        print("\n[*] Testing default credentials")
        use_tls = self.port in (8883, 8884)
        creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "public"),
            ("mqtt", "mqtt"), ("user", "user"), ("guest", "guest"),
            ("admin", ""), ("mosquitto", "mosquitto"), ("emqx", "public"),
        ]

        for user, pwd in creds:
            packet = self._build_connect(
                client_id="otaud_cred_test",
                username=user,
                password=pwd
            )
            response = self._send_receive(packet, use_tls=use_tls)
            if response and len(response) >= 4 and response[3] == 0:
                print(f"  [!] Default creds WORK: {user}:{pwd}")
                self.findings.append({
                    "severity": "CRITICAL",
                    "check": "Default Credentials",
                    "detail": f"Accepted credentials: {user}:{pwd}"
                })
                return True

        print("  [+] No common default credentials accepted")
        return False

    def check_wildcard_subscribe(self):
        """Test if wildcard topic subscription is allowed."""
        print("\n[*] Testing wildcard topic subscription (#)")
        use_tls = self.port in (8883, 8884)

        # First connect
        connect_pkt = self._build_connect(client_id="otaud_sub_test")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)
            sock.connect((self.target, self.port))
            sock.send(connect_pkt)
            connack = sock.recv(256)

            if connack and len(connack) >= 4 and connack[3] == 0:
                # Send SUBSCRIBE to # (wildcard)
                topic = b'#'
                sub_payload = struct.pack('>H', 1)  # Packet ID
                sub_payload += struct.pack('>H', len(topic)) + topic
                sub_payload += struct.pack('B', 0)  # QoS 0

                sub_packet = struct.pack('B', self.MQTT_SUBSCRIBE)
                sub_packet += self._encode_remaining_length(len(sub_payload))
                sub_packet += sub_payload

                sock.send(sub_packet)
                suback = sock.recv(256)

                if suback and (suback[0] & 0xF0) == self.MQTT_SUBACK:
                    granted_qos = suback[-1] if len(suback) > 4 else 0x80
                    if granted_qos != 0x80:
                        print("  [!] Wildcard subscription (#) ACCEPTED")
                        self.findings.append({
                            "severity": "CRITICAL",
                            "check": "Wildcard Subscribe",
                            "detail": "Topic # accessible — all messages exposed"
                        })
                    else:
                        print("  [+] Wildcard subscription refused (good)")
                else:
                    print("  [-] No SUBACK received")

            sock.close()
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
            print(f"  [-] Error: {e}")

    def check_sys_topics(self):
        """Check if $SYS topics are accessible (information disclosure)."""
        print("\n[*] Checking $SYS topic access")
        # $SYS topics expose broker internals (version, uptime, client count, etc.)
        self.findings.append({
            "severity": "MEDIUM",
            "check": "$SYS Topics",
            "detail": "Subscribe to $SYS/# to check for broker info disclosure"
        })

    def check_tls_config(self):
        """Check TLS configuration on secure port."""
        if self.port != 8883:
            print(f"\n[*] Checking if TLS is available on port 8883")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=self.target)
                tls_sock.connect((self.target, 8883))
                cert = tls_sock.getpeercert(binary_form=True)
                version = tls_sock.version()
                print(f"  [+] TLS available on 8883 (version: {version})")
                tls_sock.close()
                self.findings.append({
                    "severity": "INFO",
                    "check": "TLS Available",
                    "detail": f"MQTT/TLS on port 8883 ({version})"
                })
            except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
                print("  [-] No TLS on port 8883")
                self.findings.append({
                    "severity": "HIGH",
                    "check": "No TLS",
                    "detail": "MQTT/TLS (port 8883) not available"
                })

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  MQTT BROKER AUDIT REPORT")
        print(f"  Target: {self.target}:{self.port}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        for f in self.findings:
            sev = f["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] {f['check']}: {f['detail']}")

        print("\n  RECOMMENDATIONS:")
        print("  1. Require username/password or client certificates")
        print("  2. Use MQTT over TLS (port 8883)")
        print("  3. Implement topic-based ACLs")
        print("  4. Block wildcard (#) subscriptions")
        print("  5. Restrict $SYS topic access")
        print("  6. Enable MQTT v5 enhanced authentication")
        print("=" * 60)
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="OTAUD MQTT Broker Auditor")
    parser.add_argument("--target", "-t", required=True, help="Target IP")
    parser.add_argument("--port", "-p", type=int, default=1883)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    auditor = MQTTAuditor(args.target, args.port, args.timeout)
    if not auditor.check_connectivity():
        sys.exit(1)

    auditor.check_anonymous_access()
    auditor.check_default_credentials()
    auditor.check_wildcard_subscribe()
    auditor.check_sys_topics()
    auditor.check_tls_config()
    findings = auditor.generate_report()

    if args.json:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
