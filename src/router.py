#!/usr/bin/env python3.7

import socket
import binascii
import struct
from pascy.l2 import *
from pascy.l3 import *
from pascy.l4 import *
from pascy.layer import *
from pascy.fields import *
from dataclasses import dataclass
from collections import namedtuple


@dataclass
class RoutingTable:
    """
    Holds the routing table the a router is using. Enables 
    to resolve the next interface to forward a packet. """

    ENDIANITY = 'big'

    routing_table: list
    
    def route(self, dest_ip):
        '''
        Determine the interface through which the router should 
        forward packets to get to the destination ip address.

        :param dest_ip: the ip address of the destination
        :returns: the resolved interface ip
        :rtype: string
        '''
        self.routing_table.sort(reverse=True, key= lambda entry : entry[1])
        for entry in self.routing_table:
            dest_ip_int = int.from_bytes(socket.inet_aton(dest_ip), RoutingTable.ENDIANITY)
            mask_int = int.from_bytes(entry.mask, RoutingTable.ENDIANITY)
            entry_subnet_int = int.from_bytes(socket.inet_aton(entry.subnet), RoutingTable.ENDIANITY)
            if dest_ip_int & mask_int == entry_subnet_int:
                return entry.interface_ip
        return None
    

class Router:
    DEFAULT = '0.0.0.0'
    MASK_24_SUBNET = socket.inet_aton('255.255.255.0')
    DEFAULT_MASK = socket.inet_aton('0.0.0.0')
    NET1_NAME = 'net1'
    NET2_NAME = 'net2'
    NET1_IP = '1.1.1.1'
    NET2_IP = '2.2.2.1'
    CLIENT2_IP = '2.2.2.2'
    CLIENT1_IP = '1.1.1.2'
    
    ETH_TYPE_ARP = b'\x08\x06'
    ETH_TYPE_IPV4 = b'\x08\x00'
    BUF_SIZE = 2048
    GGP = 0x0003

    MAC_ROUTER_NET1 = '02:42:36:E0:40:43'
    MAC_ROUTER_NET2 = '02:42:00:33:82:46'
    CLIENT1_MAC = '02:42:01:01:01:02'
    CLIENT2_MAC = '02:42:02:02:02:02'

    INTERFACE_MAC2NAME = {MAC_ROUTER_NET1: NET1_NAME,
                        MAC_ROUTER_NET2: NET2_NAME}

    INTERFACE_NAME2IP = {NET1_NAME: NET1_IP,
                        NET2_NAME: NET2_IP}

    def __init__(self):
        Interface = namedtuple('Interface', ['ip', 'mac', 'name'])
        net1 = Interface(socket.inet_aton(Router.NET1_IP), Router.MAC_ROUTER_NET1, Router.NET1_NAME)
        net2 = Interface(socket.inet_aton(Router.NET2_IP), Router.MAC_ROUTER_NET2, Router.NET2_NAME)
        self.interfaces = { net1.name: net1,
                            net2.name: net2}
        self.arp_tbl = {}
        RouteEntry = namedtuple('RouteEntry', ['subnet', 'mask', 'interface_ip'])
        routes = [RouteEntry(Router.DEFAULT, Router.DEFAULT_MASK, None),
                  RouteEntry('1.1.1.0', Router.MASK_24_SUBNET, Router.NET1_IP),
                  RouteEntry('2.2.2.0', Router.MASK_24_SUBNET, Router.NET2_IP)]
        self.routing_tbl = RoutingTable(routes)

    def handle_ether(self, ether_struct, interface):
        '''
        Handles Ethernet packets by their ethernet type.
        Triggers the relevant router's activity, including sending 
        response packet (if neccessary).

        :param ether_struct: the entire deconstructed packet as a Layers hirarchy.
        '''
        if ether_struct.get_ether_type() == ArpLayer.ETHR_TYPE:
            response_packet = self.handle_arp(ether_struct, interface)
            interface = interface  
        elif ether_struct.get_ether_type() == IPv4Layer.ETHR_TYPE:
            response_packet = self.handle_ip(ether_struct, interface)
            if response_packet is None:
                return
            src_mac = MacAddress.mac2str(response_packet.get_src())
            interface = self.INTERFACE_MAC2NAME[src_mac]
        
        if response_packet is None:
            return
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(Router.GGP)) as raw_socket:
            raw_socket.bind((interface, 0))
            raw_socket.send(response_packet.build())

    def handle_arp(self, packet, interface):
        '''
        Handles ARP requests by unpacking them and constructing a respose packet (if needded).

        :param packet: the entire deconstructed packet
        :returns: a response packet after arp handling
        '''
        interface = self.interfaces[interface]
        arp_request = packet.next_layer
        if (arp_request.get_opcode() == ArpLayer.OP_IS_AT) or (arp_request.get_dest_ip() != interface.ip):
            return None
        
        response_packet = EthernetLayer() / ArpLayer()
        response_packet.set_dst(packet.get_src())
        response_packet.set_src(interface.mac)
        response_packet.set_ether_type(ArpLayer.ETHR_TYPE)
        
        arp_header = response_packet.next_layer
        arp_header.set_opcode(ArpLayer.OP_IS_AT)
        arp_header.set_src_mac(interface.mac)
        arp_header.set_src_ip(interface.ip)
        arp_header.set_dest_mac(arp_request.get_src_mac())
        arp_header.set_dest_ip(arp_request.get_src_ip())

        self.arp_tbl[arp_request.get_src_ip()] = arp_request.get_src_mac()
        return response_packet

    def handle_ip(self, packet, interface):
        '''
        Handles IP requests by unpacking them and find the new destination
        of the packet. Constructing a respose packet.

        :param packet: the entire deconstructed packet
        :returns: a packet to route
        '''
        ip_layer = packet.next_layer
        dest_ip = socket.inet_ntoa(ip_layer.get_dest_ip())
        route_interface_ip = self.routing_tbl.route(dest_ip)

        if route_interface_ip is None:
            # Unreachable. Drop
            return None
        
        elif self.INTERFACE_NAME2IP[interface] == route_interface_ip:
            if dest_ip not in [inter.ip for inter in self.interfaces.values()]:
                # Common netwok. Drop
                return None
        # ICMP
        if ip_layer.get_protocol() == ICMPLayer.PROTOCOL_ID:
            if dest_ip == Router.CLIENT2_IP:
                packet.set_dst(Router.CLIENT2_MAC)
                packet.set_src(Router.MAC_ROUTER_NET2)
            elif dest_ip == Router.CLIENT1_IP:
                packet.set_dst(Router.CLIENT1_MAC)
                packet.set_src(Router.MAC_ROUTER_NET1)
        else:   # UDP/TCP - will be implemented 
            return None

        return packet

    def observe_traffic(self):
        '''
        Gets incoming packets from net1 net2 interfaces and handles them.
        '''
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(Router.GGP)) as raw_socket:
            while True:
                packet, interface = raw_socket.recvfrom(Router.BUF_SIZE)
                requested_interface = interface[0]
                self.interfaces.keys()
                if requested_interface not in list(self.interfaces.keys()):
                    continue

                layer_struct = EthernetLayer()
                layer_struct.deconstruct(packet)
                # Drop outcoming packets
                if MacAddress.mac2str(layer_struct.get_src()) in [Router.MAC_ROUTER_NET1, Router.MAC_ROUTER_NET2]:
                    continue
                self.handle_ether(layer_struct, requested_interface)


if __name__ == '__main__':
    router = Router()
    router.observe_traffic()
