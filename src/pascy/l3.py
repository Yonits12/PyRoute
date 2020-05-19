from pascy.layer import Layer
from pascy.fields import UnsignedByte, UnsignedShort, MacAddress, IPv4Address
from pascy.l4 import ICMPLayer



class IPv4Layer(Layer):
    NAME = "IPv4"
    ETHR_TYPE = 0x800
    PROTO_SIZE = 0x04
    HW_TYPE = 0x0001
    HW_SIZE = 0x06
    CONNECTOR_FIELD = "protocol"

    SUB_LAYERS = [
        # TCP/UDP
        [ICMPLayer, CONNECTOR_FIELD, ICMPLayer.PROTOCOL_ID]
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
