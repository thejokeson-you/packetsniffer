"""
WRITTEN BY MILAN A.K.A "thejokeson-you" ON GITHUB
ETHERNET FRAME:
    - A standardised structure used for encapsulating & transmitting data across a network

    Frame contains the following:
        - Preamble & SFD (not needed for this program; important but it's more technical)
        - Ethernet Header
            - Source MAC/physical address
            - Destination MAC/physical address
            - Length/type; can be IPv4, IPv6 or ARP request/response
        - Payload/Data; main part of frame that takes up the most bytes
        - Frame Check Sequence (CRC) (like first one, not needed here, used to make sure all data sent is received)

    This packet sniffer should display details about the ethernet header & the payload












"""