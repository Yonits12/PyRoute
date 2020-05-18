from pascy.layer import Layer
from pascy.fields import UnsignedByte, UnsignedShort, MacAddress, IPv4Address
from pascy.l3 import IPv4Layer


class ArpLayer(Layer):
    NAME = "ARP"
    OP_WHO_HAS = 1
    OP_IS_AT = 2
    ETHR_TYPE = 0x806
    HW_TYPE = 0x0001
    HW_SIZE = 0x06
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
        return [UnsignedShort("hw_type", ArpLayer.HW_TYPE),
                UnsignedShort("prot_type", IPv4Layer.ETHR_TYPE),
                UnsignedByte("hw_size", ArpLayer.HW_SIZE),
                UnsignedByte("prot_size", IPv4Layer.PROTO_SIZE),
                UnsignedShort("opcode", ArpLayer.OP_WHO_HAS),
                MacAddress("src_mac"),
                IPv4Address("src_ip"),
                MacAddress("dst_mac", ArpLayer.MAC_UNKNOWN),
                IPv4Address("dst_ip")]



class EthernetLayer(Layer):
    NAME = "Ethernet"
    CONNECTOR_FIELD = "ether_type"
    MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
    

    SUB_LAYERS = [
        [ArpLayer, CONNECTOR_FIELD, ArpLayer.ETHR_TYPE],
        [IPv4Layer, CONNECTOR_FIELD, IPv4Layer.ETHR_TYPE],
    ]

    # Getters
    def get_dest(self):
        return self.fields["dst"].get()
    
    def get_src(self):
        return self.fields["src"].get()
    
    def get_ether_type(self):
        return self.fields["ether_type"].get()

    # Setters
    def set_dst(self, val):
        self.fields["dst"].set(val)
    
    def set_src(self, val):
        self.fields["src"].set(val)
    
    def set_ether_type(self, val):
        self.fields["ether_type"].set(val)

    @staticmethod
    def fields_info():
        return [MacAddress("dst", EthernetLayer.MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]

