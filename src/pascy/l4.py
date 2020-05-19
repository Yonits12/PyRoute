from pascy.layer import Layer
from pascy.fields import UnsignedByte, UnsignedShort, ByteString




class UDPLayer(Layer):
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



class ICMPLayer(Layer):
    TYPE_ECHO_REPLY = 0
    TYPE_ECHO_REQST = 8
    CODE_ECHO = 0
    PROTOCOL_ID = 1
    SIZE_OF_DATA = 56

    NAME = "ICMP"

    SUB_LAYERS = [] # FTP/SSH/NC

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

