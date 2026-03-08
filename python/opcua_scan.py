#!/usr/bin/env python3
"""
OTAUD — OPC-UA Security Scanner
Checks OPC Unified Architecture servers for security misconfigurations.
Author: Ali AlEnezi (SiteQ8)
"""

import argparse
import socket
import struct
import ssl
import sys
import json
from datetime import datetime


class OPCUAScanner:
    """OPC-UA (OPC Unified Architecture) security scanner."""

    OPCUA_PORT = 4840
    MSG_HELLO = b'HEL'
    MSG_ACK = b'ACK'

    def __init__(self, target, port=4840, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.findings = []

    def check_connectivity(self):
        print(f"\n[*] Checking OPC-UA server: {self.target}:{self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            print(f"  [+] OPC-UA port {self.port} is OPEN")
            self.findings.append({"severity": "INFO", "check": "Connectivity",
                                  "detail": f"OPC-UA port {self.port} accessible"})
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Cannot connect: {e}")
            return False

    def send_hello(self):
        """Send OPC-UA Hello message to discover endpoint."""
        print("\n[*] Sending OPC-UA Hello message")
        endpoint_url = f"opc.tcp://{self.target}:{self.port}".encode()

        # Hello message: Type(3) + Reserved(1) + Size(4) + ProtocolVersion(4) +
        # ReceiveBufferSize(4) + SendBufferSize(4) + MaxMessageSize(4) +
        # MaxChunkCount(4) + EndpointUrlLength(4) + EndpointUrl
        payload = struct.pack('<IIIII',
                              0,          # Protocol version
                              65535,      # Receive buffer
                              65535,      # Send buffer
                              0,          # Max message size (0=no limit)
                              0)          # Max chunk count
        payload += struct.pack('<I', len(endpoint_url)) + endpoint_url

        msg = self.MSG_HELLO + b'F'  # Final chunk
        msg += struct.pack('<I', 8 + len(payload))  # Message size
        msg += payload

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(msg)
            response = sock.recv(4096)
            sock.close()

            if response and len(response) >= 8:
                msg_type = response[0:3]
                if msg_type == self.MSG_ACK:
                    print("  [+] OPC-UA Acknowledge received — valid OPC-UA server")
                    if len(response) >= 28:
                        proto_ver = struct.unpack('<I', response[8:12])[0]
                        recv_buf = struct.unpack('<I', response[12:16])[0]
                        send_buf = struct.unpack('<I', response[16:20])[0]
                        max_msg = struct.unpack('<I', response[20:24])[0]
                        max_chunk = struct.unpack('<I', response[24:28])[0]
                        print(f"      Protocol Version: {proto_ver}")
                        print(f"      Buffer Sizes: recv={recv_buf}, send={send_buf}")
                        print(f"      Max Message: {max_msg}, Max Chunks: {max_chunk}")
                        self.findings.append({
                            "severity": "INFO",
                            "check": "Server Info",
                            "detail": f"OPC-UA v{proto_ver}, buffers={recv_buf}/{send_buf}"
                        })
                elif msg_type == b'ERR':
                    if len(response) >= 12:
                        error_code = struct.unpack('<I', response[8:12])[0]
                        error_msg = response[16:].decode('utf-8', errors='replace') if len(response) > 16 else ""
                        print(f"  [-] OPC-UA Error: code={error_code:#010x} msg={error_msg}")
                else:
                    print(f"  [~] Unknown response type: {msg_type}")
            return response
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Error: {e}")
            return None

    def check_security_policies(self):
        """Check available security policies via HTTP discovery."""
        print("\n[*] Checking OPC-UA security policies (HTTP discovery)")
        for port in [self.port, 4843, 443, 8443]:
            try:
                import urllib.request
                url = f"http://{self.target}:{port}/discovery"
                req = urllib.request.Request(url, headers={'User-Agent': 'OTAUD/1.0'})
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                body = resp.read().decode('utf-8', errors='replace')
                if 'security' in body.lower() or 'endpoint' in body.lower():
                    print(f"  [+] Discovery endpoint on port {port}")
                    self.findings.append({
                        "severity": "INFO",
                        "check": "Discovery Endpoint",
                        "detail": f"HTTP discovery available on port {port}"
                    })
            except Exception:
                pass

        # Check for None security policy (most dangerous)
        print("  [*] Key security policy checks:")
        print("      - SecurityPolicy#None: MUST be disabled (allows plaintext)")
        print("      - SecurityPolicy#Basic128Rsa15: DEPRECATED (weak crypto)")
        print("      - SecurityPolicy#Basic256: Acceptable (minimum)")
        print("      - SecurityPolicy#Basic256Sha256: RECOMMENDED")
        print("      - SecurityPolicy#Aes128_Sha256_RsaOaep: BEST")

        self.findings.append({
            "severity": "HIGH",
            "check": "Security Policy",
            "detail": "Verify SecurityPolicy#None is disabled; use Basic256Sha256+"
        })

    def check_anonymous_auth(self):
        """Check if anonymous authentication is enabled."""
        print("\n[*] Checking for anonymous authentication")
        print("  [*] Manual verification needed via OPC-UA client:")
        print("      1. Connect with UaExpert or Prosys OPC-UA Browser")
        print("      2. Check if Anonymous identity token is accepted")
        print("      3. Verify UserTokenPolicy list in GetEndpoints response")

        self.findings.append({
            "severity": "HIGH",
            "check": "Anonymous Auth",
            "detail": "Verify anonymous authentication is disabled on server"
        })

    def check_certificate_security(self):
        """Check TLS/certificate configuration."""
        print("\n[*] Checking certificate configuration")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            tls_sock = ctx.wrap_socket(sock, server_hostname=self.target)
            tls_sock.connect((self.target, self.port))
            cert = tls_sock.getpeercert()
            version = tls_sock.version()
            cipher = tls_sock.cipher()
            print(f"  [+] TLS version: {version}")
            print(f"  [+] Cipher: {cipher[0] if cipher else 'unknown'}")
            if cert:
                print(f"  [+] Certificate subject: {cert.get('subject', 'unknown')}")
            tls_sock.close()

            self.findings.append({
                "severity": "INFO",
                "check": "TLS Config",
                "detail": f"TLS {version}, cipher: {cipher[0] if cipher else 'unknown'}"
            })
        except ssl.SSLError:
            print("  [~] OPC-UA binary protocol (no TLS wrapper) — uses app-layer security")
            self.findings.append({
                "severity": "INFO",
                "check": "Transport",
                "detail": "Binary protocol — relies on OPC-UA application-layer security"
            })
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Error: {e}")

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  OPC-UA SECURITY AUDIT REPORT")
        print(f"  Target: {self.target}:{self.port}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        for f in self.findings:
            sev = f["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "INFO": "🔵"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] {f['check']}: {f['detail']}")

        print("\n  RECOMMENDATIONS:")
        print("  1. Enforce SignAndEncrypt security mode")
        print("  2. Disable SecurityPolicy#None and Basic128Rsa15")
        print("  3. Disable anonymous authentication")
        print("  4. Use X.509 certificates with proper PKI")
        print("  5. Implement role-based access via OPC-UA RBAC")
        print("  6. Enable audit logging on OPC-UA server")
        print("=" * 60)
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="OTAUD OPC-UA Scanner")
    parser.add_argument("--target", "-t", required=True, help="Target IP/hostname")
    parser.add_argument("--port", "-p", type=int, default=4840)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    scanner = OPCUAScanner(args.target, args.port, args.timeout)
    if not scanner.check_connectivity():
        sys.exit(1)

    scanner.send_hello()
    scanner.check_security_policies()
    scanner.check_anonymous_auth()
    scanner.check_certificate_security()
    findings = scanner.generate_report()

    if args.json:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
