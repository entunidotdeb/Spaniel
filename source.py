import socket
import textwrap
import struct

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while(True):
        raw_data, addr = conn.recvfrom(65536)
        #print("Raw data {}".format(raw_data))
        #print("address {}".format(addr))
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\n Ethernet Frame: ")
        print("Destination {}, source {}, Protocol {}".format(dest_mac, src_mac, eth_proto))
        if eth_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = ipv4_packet(data)
            print("IPv4 Packet: ")
            print("Version {}, Header Length: {}, TTL: {}".format(version, header_len,ttl))
            print("Protocol {}, Source: {}, Target: {}".format(proto, src, target))
            if proto==1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print("ICMP Packet:")
                print("Type: {}, Code: {}, checksum: {}".format(icmp_type, code, checksum))
                print("Data: ")
                print(format_multi_line('\t\t\t   ', data))
            elif proto==6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin) = tcp_segment(data)
                print("TCP Segment: ")
                print("Source port: {}, Destination Port: {}".format(src_port,dest_port))
                print("sequence: {}, acknowledgement: {}".format(sequence, acknowledgement))
                print("Flags: ")
                print("URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {} ".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print("Data: ")
                print(format_multi_line('\t\t\t   ',data))
            elif proto == 17:
                src_port, dest_port, Length, data = udp_segment(data)
                print("UDP Segment: ")
                print("Source Port: {}, Destination port {}, Length {}".format(src_mac, dest_port, Length))
            else:
                print("Data: ")
                print(format_multi_line('\t\t\t   ', data))
        else:
            print("Data: ")
            print(format_multi_line('\t\t\t   ',data))
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
    #print("Version {} \n Header len {} \n TTL {} \n Protocol {} \n Source {} \n Destination/Target {} data{}".format(version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]))
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_packet(data):
    icmp_type, code , checksum = struct.unpack("! B B H",data[:4])
    return icmp_type, code , checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack("! H H L L H",data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]
def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H",data[:8])
    return src_port,dest_port, size, data[8:]
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
main()
