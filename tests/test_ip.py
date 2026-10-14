import socket
import struct

if __name__ == '__main__':
    ip = "10.0.0.1"
    ip_bytes = socket.inet_aton(ip)

    # network byte order (big endian)
    ip_net = struct.unpack("!I", ip_bytes)[0]

    # host byte order (little endian, assuming x86_64)
    ip_host = struct.unpack("<I", ip_bytes)[0]

    print(f"Network (big): {ip_net} (0x{ip_net:08x})")
    print(f"Host (little): {ip_host} (0x{ip_host:08x})")

