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

    @staticmethod
    def fields_info():
        return [MacAddress("dst", EthernetLayer.MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]
