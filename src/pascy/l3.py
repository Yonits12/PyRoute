from pascy.layer import Layer
from pascy.fields import *
from pascy.l4 import ICMPLayer

HW_TYPE = 0x0001
HW_SIZE = 0x06

class ArpLayer(Layer):
    NAME = "ARP"
    OP_WHO_HAS = 1
    OP_IS_AT = 2
    ETHR_TYPE = 0x806
    MAC_UNKNOWN = "00:00:00:00:00:00"

    SUB_LAYERS = []

    @staticmethod
    def fields_info():
        # Hardware type, Protocol type, Hardware size, Protocol size, Opcode, src MAC, src IP, dst MAC, dst IP 2s2s1s1s2s6s4s6s4s
        return [UnsignedShort("hw_type", HW_TYPE),
                UnsignedShort("prot_type", IPv4Layer.ETHR_TYPE),
                UnsignedByte("hw_size", HW_SIZE),
                UnsignedByte("prot_size", IPv4Layer.PROTO_SIZE),
                UnsignedShort("opcode", ArpLayer.OP_WHO_HAS),
                MacAddress("src"),
                IPv4Address("src"),
                MacAddress("dst", ArpLayer.MAC_UNKNOWN),
                IPv4Address("dst")]


class IPv4Layer(Layer):
    NAME = "IPv4"
    ETHR_TYPE = 0x800
    PROTO_SIZE = 0x04
    CONNECTOR_FIELD = "protocol"

    SUB_LAYERS = [
        # TCP/UDP
        [ICMPLayer, CONNECTOR_FIELD, ICMPLayer.PROTOCOL_ID]
        # FTP/SSH/NC
    ]

    @staticmethod
    def fields_info():
        return [UnsignedByte("version|IHL"),
                UnsignedByte("type_of_service"),
                UnsignedShort("total_length"),
                UnsignedShort("identigication"),
                UnsignedShort("flags|frag_offset"),
                UnsignedByte("ttl"),
                UnsignedByte("protocol"),
                UnsignedShort("header_checksum"),
                IPv4Address("src"),
                IPv4Address("dst")]



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
