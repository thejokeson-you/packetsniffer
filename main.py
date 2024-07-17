import struct  # Handles binary data in files, will need to interpret all data in frame
import socket  # access to BSD socket interface (an API for internet sockets)
import textwrap


def get_mac_address(address):
    """
    change MAC address into the format AA:BB:CC:DD:EE:FF
    :param address: the MAC address to reformat
    :return: MAC address in the correct format
    """
    bytes_str = map('{:02x}'.format, address)
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
