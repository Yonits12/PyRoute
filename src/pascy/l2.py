from pascy.layer import Layer
from pascy.fields import *
from pascy.l3 import ArpLayer, IPv4Layer


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
