from pascy.layer import Layer
from pascy.fields import *

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
MAC_UNKNOWN = "00:00:00:00:00:00"
ETHER_TYPE = 0x0001
IPV4_TYPE = 0x0800
ETHER_SIZE = 0x06
IPV4_SIZE = 0x04


class ArpLayer(Layer):
    OP_WHO_HAS = 1
    OP_IS_AT = 2

    NAME = "ARP"

    @staticmethod
    def fields_info():
        # TODO: Implement this :)
        # Hardware type, Protocol type, Hardware size, Protocol size, Opcode, src MAC, src IP, dst MAC, dst IP 2s2s1s1s2s6s4s6s4s
        return [UnsignedShort("hw_type", ETHER_TYPE),
                UnsignedShort("prot_type", IPV4_TYPE),
                UnsignedByte("hw_size", ETHER_SIZE),
                UnsignedByte("prot_size", IPV4_SIZE),
                UnsignedShort("opcode", ArpLayer.OP_WHO_HAS),
                MacAddress("src"),
                IPv4Address("src"),
                MacAddress("dst", MAC_UNKNOWN),
                IPv4Address("dst")]


class IPv4Layer(Layer):
    NAME = "IPv4"

    SUB_LAYERS = [
        # TCP/UDP or transport layer packets
        # FTP/SSH/NC
    ]

    @staticmethod
    def fields_info():      # 1s1s2s2s2s1s1s2s4s4s
        return [UnsignedByte("version|IHL"),
                UnsignedByte("ECN|total_length"),
                UnsignedShort("identigication"),
                UnsignedShort("flags|frag_offset"),
                UnsignedByte("ttl"),
                UnsignedByte("protocol"),
                UnsignedShort("header_checksum"),
                IPv4Address("src"),
                IPv4Address("dst")]


class EthernetLayer(Layer):
    NAME = "Ethernet"

    SUB_LAYERS = [
        [ArpLayer, "ether_type", 0x806],
        [IPv4Layer, "ether_type", 0x800],
    ]

    @staticmethod
    def fields_info():
        return [MacAddress("dst", MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]


# ===========================================================================
# IP header info from RFC791
#   -> http://tools.ietf.org/html/rfc791)
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |Type of Service|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ===========================================================================
# ICMP Echo / Echo Reply Message header info from RFC792
#   -> http://tools.ietf.org/html/rfc792
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     Type      |     Code      |          Checksum             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           Identifier          |        Sequence Number        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |     Data ...
#     +-+-+-+-+-
# ===========================================================================

