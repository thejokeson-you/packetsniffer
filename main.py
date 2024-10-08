import struct  # Handles binary data in files, will need to interpret all data in frame
import socket  # access to BSD socket interface (an API for internet sockets)
import textwrap

tab1 = '\t - '
tab2 = '\t\t - '
tab3 = '\t\t\t - '
tab4 = '\t\t\t\t - '

data_tab1 = '\t '
data_tab2 = '\t\t '
data_tab3 = '\t\t\t '
data_tab4 = '\t\t\t\t '


def main():
    """
    Infinite loop main method which listens for packets from which data is extracted & outputted
    MAKE SURE IDE IS RUNNING WITH ADMIN PRIVILEGES IF TESTING.
    """

    host = socket.gethostbyname(socket.gethostname())  # Raw socket
    # Create socket to allow connections with other computers
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))  # Bind raw socket to public interface
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Receive all packets

    while True:
        raw_data, address = conn.recvfrom(65535)
        dest_mac, source_mac, eth_protocol, data = unpack_ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(tab1 + 'Source: {}, Destination: {}, Protocol: {}'.format(source_mac, dest_mac, eth_protocol))

        # IPv4 is protocol 8
        if eth_protocol == 8:
            (version, header_length, ttl, proto, src, target, data) = unpack_ipv4_packet(data)
            print(tab1 + 'IPv4 Packet:')
            print(tab2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(tab2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(tab1 + 'ICMP Packet: ')
                print(tab2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
                print(tab2 + 'Data: ')
                print(format_multi_line(data_tab3, data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                 flag_fin, data) = tcp_segment(data)
                print(tab1 + 'TCP Segment: ')
                print(tab2 + 'Source port: {}, Destination port: {}'.format(src_port, dest_port))
                print(tab2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(tab2 + 'Flags: ')
                print(tab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,
                                                                                           flag_rst, flag_syn,
                                                                                           flag_fin))
                print(tab2 + 'Data: ')
                print(format_multi_line(data_tab3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(tab1 + 'UDP Segment: ')
                print(tab2 + 'Source port: {}, Destination port: {}, Length: {}'.format(src_port, dest_port, size))

            else:
                print(tab1 + 'Data: ')
                print(format_multi_line(data_tab2, data))

        else:
            print('Data: ')
            print(format_multi_line(data_tab1, data))


def get_mac_address(address):
    """
    Change MAC address into the format AA:BB:CC:DD:EE:FF
    :param address: the MAC address to reformat
    :return: MAC address in the correct format
    """
    bytes_str = map('{:02x}'.format, address)  # string format as 2-digit hexadecimal num
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def unpack_ethernet_frame(data):
    """
    Unpack the frame & interpret binary data of ethernet header using struct
    :param data: data from packet which is to be interpreted
    :return: properly formatted source & dest mac address, readable byte format of type, payload data
    """
    dest_mac, source_mac, type = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(source_mac), socket.htons(type), data[14:]


def unpack_ipv4_packet(data):
    """
    Unpack IPv4 packet data
    :param data: Data from packet
    :return: version, header length, TTL, protocol, formatted src & dest IPs, & rest of data (payload)
    """
    version_header_length = data[0]
    version = version_header_length >> 4  # bitwise shift to push out header length so only version is left in data[0]
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, formatted_ipv4(src), formatted_ipv4(target), data[header_length:]


def formatted_ipv4(address):
    """
    Rewrite IPv4 address in correct format a.b.c.d
    :param address: IPv4 address to format
    :return: Correctly formatted IPv4 address
    """
    return '.'.join(map(str, address))


def icmp_packet(data):
    """
    Unpack ICMP data
    :param data:
    :return:
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    """
    Unpack TCP segment
    :param data:
    :return:
    """
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                       offset:]


# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Correctly formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
