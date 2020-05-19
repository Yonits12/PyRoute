from pascy.layer import Layer
from pascy.fields import UnsignedByte, UnsignedShort, UnsignedInteger, ByteString


class UDPLayer(Layer):
    PROTOCOL_ID = 17
    NAME = "UDP"

    SUB_LAYERS = [] # DNS

    @staticmethod
    def fields_info():
        return [UnsignedShort("src_port", 0),
                UnsignedShort("dst_port", 0),
                UnsignedShort("length", 0),
                UnsignedShort("checksum", 0)]


class TCPLayer(Layer):
    PROTOCOL_ID = 6
    NAME = "TCP"

    SUB_LAYERS = [] # FTP/SSH/NC

    @staticmethod
    def fields_info():
        return [UnsignedShort("src_port", 0),
                UnsignedShort("dst_port", 0),
                UnsignedInteger("seq_num", 0),
                UnsignedInteger("ack_num", 0),
                UnsignedByte('data_res_NS'),
                UnsignedByte('flags'),
                UnsignedShort('window_size'),
                UnsignedShort('checksum'),
                UnsignedShort('urgent_pointer')] # options with variable length.
