#!/usr/bin/env python3
import socket
import struct
import time
import sys

def checksum(data):
    """Calculate ICMP checksum"""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i + 1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def send_icmp_timestamp(target):
    """Send ICMP Type 13 (Timestamp Request)"""
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(5)
        
        # ICMP Type 13 (Timestamp Request)
        icmp_type = 13
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 1234
        icmp_seq = 1
        
        # Timestamp fields (milliseconds since midnight UTC)
        # Originate timestamp
        current_time = int((time.time() % 86400) * 1000)
        receive_timestamp = 0
        transmit_timestamp = 0
        
        # Pack ICMP header + timestamp data
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = struct.pack('!III', current_time, receive_timestamp, transmit_timestamp)
        
        # Calculate checksum
        icmp_checksum = checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_seq)
        
        packet = header + data
        
        # Send packet
        print(f"Sending ICMP Type 13 (Timestamp Request) to {target}")
        sock.sendto(packet, (target, 0))
        print(f"Packet sent successfully!")
        
        # Try to receive response
        try:
            data, addr = sock.recvfrom(1024)
            print(f"\nReceived response from {addr[0]}")
            
            # Parse IP header (first 20 bytes typically)
            ip_header = data[:20]
            icmp_data = data[20:]
            
            if len(icmp_data) >= 20:
                icmp_type_resp, icmp_code_resp, _, _, _ = struct.unpack('!BBHHH', icmp_data[:8])
                print(f"ICMP Type: {icmp_type_resp}, Code: {icmp_code_resp}")
                
                if icmp_type_resp == 14:  # Timestamp Reply
                    orig, recv, trans = struct.unpack('!III', icmp_data[8:20])
                    print(f"Originate Timestamp: {orig} ms")
                    print(f"Receive Timestamp: {recv} ms")
                    print(f"Transmit Timestamp: {trans} ms")
        except socket.timeout:
            print("No response received (timeout)")
        
        sock.close()
        
    except PermissionError:
        print("Error: Need root/sudo privileges to create raw sockets")
        sys.exit(1)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {target}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 icmp_timestamp.py <target_ip_or_hostname>")
        sys.exit(1)
    
    target = sys.argv[1]
    send_icmp_timestamp(target)
