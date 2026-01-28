#!/usr/bin/env python3
import socket
import struct
import time
import sys
import select

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

def send_icmp_timestamp(target, timeout=10):
    """Send ICMP Type 13 (Timestamp Request) and capture response"""
    try:
        # Resolve target
        target_ip = socket.gethostbyname(target)
        print(f"Target resolved to: {target_ip}")
        
        # Create raw socket for sending
        sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Create raw socket for receiving - bind to catch all ICMP
        sock_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock_recv.bind(('', 0))
        sock_recv.settimeout(timeout)
        
        # ICMP Type 13 (Timestamp Request)
        icmp_type = 13
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 0x1234
        icmp_seq = 1
        
        # Timestamp fields (milliseconds since midnight UTC)
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
        print(f"\nSending ICMP Type 13 (Timestamp Request) to {target_ip}")
        print(f"  ID: 0x{icmp_id:04x}, Seq: {icmp_seq}")
        print(f"  Originate Timestamp: {current_time} ms")
        
        send_time = time.time()
        sock_send.sendto(packet, (target_ip, 0))
        print(f"  Packet sent at {time.strftime('%H:%M:%S', time.localtime(send_time))}")
        
        # Wait for response
        print(f"\nWaiting for response (timeout: {timeout}s)...")
        
        attempts = 0
        max_attempts = 50  # Try receiving multiple packets
        
        while attempts < max_attempts:
            try:
                ready = select.select([sock_recv], [], [], timeout)
                if not ready[0]:
                    print("Timeout - no response received")
                    break
                
                data, addr = sock_recv.recvfrom(1024)
                attempts += 1
                recv_time = time.time()
                
                # Parse IP header to get actual source
                ip_header = data[:20]
                ihl = (ip_header[0] & 0x0F) * 4  # IP Header Length
                src_ip = socket.inet_ntoa(ip_header[12:16])
                
                # Only process packets from our target
                if src_ip != target_ip:
                    continue
                
                icmp_data = data[ihl:]
                
                if len(icmp_data) >= 8:
                    icmp_type_resp, icmp_code_resp, checksum_resp, id_resp, seq_resp = struct.unpack('!BBHHH', icmp_data[:8])
                    
                    print(f"\n[Packet #{attempts}] Response from {src_ip}:")
                    print(f"  ICMP Type: {icmp_type_resp}, Code: {icmp_code_resp}")
                    print(f"  ID: 0x{id_resp:04x}, Seq: {seq_resp}")
                    print(f"  RTT: {(recv_time - send_time)*1000:.2f} ms")
                    
                    if icmp_type_resp == 14:  # Timestamp Reply
                        if len(icmp_data) >= 20:
                            orig, recv, trans = struct.unpack('!III', icmp_data[8:20])
                            print(f"  ✓ TIMESTAMP REPLY RECEIVED!")
                            print(f"    Originate: {orig} ms (since midnight UTC)")
                            print(f"    Receive:   {recv} ms (since midnight UTC)")
                            print(f"    Transmit:  {trans} ms (since midnight UTC)")
                            
                            # Calculate time difference
                            if recv > orig:
                                print(f"    Time diff: {recv - orig} ms (one-way latency)")
                            
                            sock_send.close()
                            sock_recv.close()
                            return True
                    elif icmp_type_resp == 3:  # Destination Unreachable
                        print(f"  ✗ Destination Unreachable (Code: {icmp_code_resp})")
                    elif icmp_type_resp == 11:  # Time Exceeded
                        print(f"  ✗ Time Exceeded (Code: {icmp_code_resp})")
                    
            except socket.timeout:
                print("Socket timeout")
                break
            except Exception as e:
                print(f"Error receiving: {e}")
                break
        
        if attempts == 0:
            print("No response received within timeout period")
        elif attempts > 0:
            print(f"\nReceived {attempts} packet(s) but no Type 14 (Timestamp Reply)")
        
        sock_send.close()
        sock_recv.close()
        return False
        
    except PermissionError:
        print("Error: Need root/sudo privileges to create raw sockets")
        print("Run with: sudo python3 icmp_timestamp.py <target>")
        sys.exit(1)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {target}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("ICMP Type 13 Timestamp Request Tool")
        print("=" * 40)
        print("Usage: sudo python3 icmp_timestamp.py <target> [timeout]")
        print("\nExamples:")
        print("  sudo python3 icmp_timestamp.py 192.168.1.1")
        print("  sudo python3 icmp_timestamp.py example.com 15")
        sys.exit(1)
    
    target = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    print("=" * 60)
    print("ICMP Type 13 Timestamp Request")
    print("=" * 60)
    
    success = send_icmp_timestamp(target, timeout)
    
    print("=" * 60)
    if success:
        print("✓ ICMP Timestamp request successful!")
    else:
        print("✗ No timestamp reply received")
        print("\nNote: Many hosts disable ICMP timestamp replies for security.")
        print("However, the request was sent successfully.")
    print("=" * 60)
