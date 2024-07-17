import struct  # Handles binary data in files, will need to interpret all data in frame
import socket  # access to BSD socket interface (an API for internet sockets)
import textwrap


def main():
    """
    Infinite loop main method which listens for packets from which data is extracted & outputted
    MAKE SURE IDE IS RUNNING WITH ADMIN PRIVILEGES IF TESTING.
    """

    host = socket.gethostbyname(socket.gethostname())   # Raw socket
    # Create socket to allow connections with other computers
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))  # Bind raw socket to public interface
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Include IP headers
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # Receive all packets

    while True:
        raw_data, address = conn.recvfrom(65535)
        dest_mac, source_mac, eth_type, data = unpack_ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Source: {}, Destination: {}, Protocol: {}'.format(source_mac, dest_mac, eth_type))


def get_mac_address(address):
    """
    change MAC address into the format AA:BB:CC:DD:EE:FF
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


main()
