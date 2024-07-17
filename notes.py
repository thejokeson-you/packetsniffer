"""
WRITTEN BY MILAN A.K.A "thejokeson-you" ON GITHUB
ETHERNET FRAME:
    - A standardised structure used for encapsulating & transmitting data across a network

    Frame contains the following:
        - Preamble & SFD (not needed for this program; important but it's more technical) (8 bytes)
        - Ethernet Header (14 bytes)
            - Source MAC/physical address (6 bytes)
            - Destination MAC/physical address (6 bytes)
            - Length/type; can be IPv4, IPv6 or ARP request/response (2 bytes)
        - Payload/Data; main part of frame that takes up the most bytes (up to 1.5kb)
        - Frame Check Sequence (CRC) (not needed for prog., used to make sure all data sent is received) (4 bytes)

    This packet sniffer should display details about the ethernet header & the payload












"""