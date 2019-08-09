import socket
import textwrap
import struct

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while(True):
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\n Ethernet Frame: ")
        print("Destination {}, source {}, Protocol {}".format(dest_mac, src_mac, eth_proto))
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(proto), data[14:]

def get_mac_add(bytes_addr):
    bytes_str = map("{:02x}".format,bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s",data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    return '.'join(map(str,addr))

main()
