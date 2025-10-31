#!/usr/bin/env python3
import socket, ssl, sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 3389

try:
    rdp_handshake = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.send(rdp_handshake)
    s.recv(8192)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ssl_sock = context.wrap_socket(s, server_hostname=host)
    cert = x509.load_der_x509_certificate(ssl_sock.getpeercert(binary_form=True), default_backend())
    print(f"Host: {host}\nSubject: {cert.subject.rfc4514_string()}\nIssuer: {cert.issuer.rfc4514_string()}\nNotBefore: {cert.not_valid_before_utc}\nNotAfter: {cert.not_valid_after_utc}\nSerial: {cert.serial_number}\nFingerprint: {cert.fingerprint(cert.signature_hash_algorithm).hex()}")
    ssl_sock.close()
except Exception as e:
    print(f"Error: {e}")