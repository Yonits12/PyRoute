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

    # Getters
    def get_src_mac(self):
        return self.fields["src_mac"].get()
    
    def get_dest_mac(self):
        return self.fields["dst_mac"].get()
    
    def get_src_ip(self):
        return self.fields["src_ip"].get()
    
    def get_dest_ip(self):
        return self.fields["dst_ip"].get()

    def get_opcode(self):
        return self.fields["opcode"].get()

    # Setters
    def set_src_mac(self, val):
        self.fields["src_mac"].set(val)
    
    def set_dest_mac(self, val):
        self.fields["dst_mac"].set(val)
    
    def set_src_ip(self, val):
        self.fields["src_ip"].set(val)
    
    def set_dest_ip(self, val):
        self.fields["dst_ip"].set(val)

    def set_opcode(self, val):
        self.fields["opcode"].set(val)

    @staticmethod
    def fields_info():
        return [UnsignedShort("hw_type", HW_TYPE),
                UnsignedShort("prot_type", IPv4Layer.ETHR_TYPE),
                UnsignedByte("hw_size", HW_SIZE),
                UnsignedByte("prot_size", IPv4Layer.PROTO_SIZE),
                UnsignedShort("opcode", ArpLayer.OP_WHO_HAS),
                MacAddress("src_mac"),
                IPv4Address("src_ip"),
                MacAddress("dst_mac", ArpLayer.MAC_UNKNOWN),
                IPv4Address("dst_ip")]


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

    # Getters
    def get_src_ip(self):
        return self.fields["src"].get()
    
    def get_dest_ip(self):
        return self.fields["dst"].get()

    def get_protocol(self):
        return self.fields["protocol"].get()

    # Setters
    def set_src_ip(self, val):
        self.fields["src"].set(val)
    
    def set_dest_ip(self, val):
        self.fields["dst"].set(val)

    def set_protocol(self, val):
        self.fields["protocol"].set(val)

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
