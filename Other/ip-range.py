#!/usr/bin/python3
import sys
import ipaddress

def undotIPv4(dotted):
    return sum(int(octet) << ((3 - i) << 3) for i, octet in enumerate(dotted.split('.')))

def dotIPv4(addr):
    return '.'.join(str(addr >> off & 0xff) for off in (24, 16, 8, 0))

def rangeIPv4(start, stop):
    # Generate IPs from start (inclusive) to stop (exclusive)
    for addr in range(undotIPv4(start), undotIPv4(stop)):
        yield dotIPv4(addr)

def print_usage():
    print("Usage:")
    print("  ip-range.py start_ip end_ip")
    print("  ip-range.py network/mask")
    sys.exit(1)

if len(sys.argv) == 2:
    # Assume CIDR notation was provided
    try:
        network = ipaddress.ip_network(sys.argv[1], strict=False)
        for ip in network:
            print(ip)
    except ValueError as e:
        print(f"Invalid network: {e}")
        sys.exit(1)
elif len(sys.argv) == 3:
    # Assume start and stop IP addresses were provided
    for x in rangeIPv4(sys.argv[1], sys.argv[2]):
        print(x)
    # The original script printed the final IP separately
    print(sys.argv[2])
else:
    print_usage()
