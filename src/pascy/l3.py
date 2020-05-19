from pascy.layer import Layer
from pascy.fields import UnsignedByte, UnsignedShort, ByteString, MacAddress, IPv4Address


class ICMPLayer(Layer):
    TYPE_ECHO_REPLY = 0
    TYPE_ECHO_REQST = 8
    CODE_ECHO = 0
    PROTOCOL_ID = 1
    SIZE_OF_DATA = 56

    NAME = "ICMP"

    SUB_LAYERS = []

    @staticmethod
    def fields_info():
        return [UnsignedByte("type", ICMPLayer.TYPE_ECHO_REQST),
                UnsignedByte("code", ICMPLayer.CODE_ECHO),
                UnsignedShort("checksum", 0),
                UnsignedShort("identifier", 0),
                UnsignedShort("sequence_number", 0),
                ByteString("data", ICMPLayer.SIZE_OF_DATA, "")]

# ===========================================================================
# 
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

    # src_ip = property(lambda self : self.fields["src"].get(), lambda self, val : self.fields["src"].set(val))
    # dest_ip = property(lambda self : self.fields["dst"].get(), lambda self, val : self.fields["dst"].set(val))
    # protocol = property(lambda self : self.fields["protocol"].get(), lambda self, val : self.fields["protocol"].set(val))

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
