#!/usr/bin/env python3.7

import socket
import binascii
import struct
from pascy.l2 import *
from pascy.l3 import *
from pascy.l4 import *
from pascy.layer import *
from pascy.fields import *


class RoutingTable:
    MASK_24_SUBNET = socket.inet_aton('255.255.255.0')
    DEFAULT = '0.0.0.0'
    NET1_IP = '1.1.1.1'
    NET2_IP = '2.2.2.1'
    ROUTING_TABLE = {(DEFAULT, DEFAULT, None),
                    ('1.1.1.0', MASK_24_SUBNET, NET1_IP),
                    ('2.2.2.0', MASK_24_SUBNET, NET2_IP)}
    
    def route(self, dest_ip):
        '''
        Determine the interface through which the router should 
        forward packets to get to the destination ip address

        :param dest_ip: the ip address of the destination
        :returns: the resolved interface ip
        :rtype: string
        '''
        for entry in RoutingTable.ROUTING_TABLE:        # TODO should be sorted
            dest_ip_int = int.from_bytes(socket.inet_aton(dest_ip), 'big')
            mask_int = int.from_bytes(RoutingTable.MASK_24_SUBNET, 'big')
            entry_subnet_int = int.from_bytes(socket.inet_aton(entry[0]), 'big')
            if dest_ip_int & mask_int == entry_subnet_int:
                return entry[2] # the interface
        return None # TODO unreachable because default


class Interface:
    
    def __init__(self, ip, mac, name):
        self.ip = socket.inet_aton(ip)
        self.mac = mac
        self.name = name
    
    def get_ip(self):
        return self.ip
    
    def get_mac(self):
        return self.mac
    
    def get_name(self):
        return self.name
    

class Router:

    DEFAULT = '0.0.0.0'
    NET1_NAME = 'net1'
    NET2_NAME = 'net2'
    NET1_IP = '1.1.1.1'
    NET2_IP = '2.2.2.1'
    
    ETH_TYPE_ARP = b'\x08\x06'
    ETH_TYPE_IPV4 = b'\x08\x00'

    MAC_ROUTER_NET1 = '02:42:36:E0:40:43'
    MAC_ROUTER_NET2 = '02:42:00:33:82:46'
    CLIENT1_MAC = '02:42:01:01:01:02'
    CLIENT2_MAC = '02:42:02:02:02:02'

    INTERFACE_MAC2NAME = {MAC_ROUTER_NET1: NET1_NAME,
                        MAC_ROUTER_NET2: NET2_NAME}

    INTERFACE_NAME2IP = {NET1_NAME: NET1_IP,
                        NET2_NAME: NET2_IP}

    CLIENT2_IP = '2.2.2.2'
    CLIENT1_IP = '1.1.1.2'
    BUF_SIZE = 2048

    def __init__(self):
        self.net1 = Interface(Router.NET1_IP, Router.MAC_ROUTER_NET1, Router.NET1_NAME)
        self.net2 = Interface(Router.NET2_IP, Router.MAC_ROUTER_NET2, Router.NET2_NAME)
        self.requested_interface = None
        self.arp_tbl = {}
        self.routing_tbl = RoutingTable()

    def handle_ether(self, ether_struct):
         # ethernet handling
        if ether_struct.get_ether_type() == ArpLayer.ETHR_TYPE:
            arp_response_packet = self.handle_arp(ether_struct)
            if arp_response_packet is None:
                return
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as arp_socket:
                arp_socket.bind((self.requested_interface, 0))
                arp_socket.send(arp_response_packet.build())

        elif ether_struct.get_ether_type() == IPv4Layer.ETHR_TYPE:
            ip_response_packet = self.handle_ip(ether_struct)
            if ip_response_packet is None:
                return
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as ip_socket:
                src_mac = ip_response_packet.get_src()
                src_mac = MacAddress.mac2str(src_mac)
                name = self.INTERFACE_MAC2NAME[src_mac]
                ip_socket.bind((name, 0))
                ip_socket.send(ip_response_packet.build())

    def handle_arp(self, packet):
        '''
        Handles ARP requests by unpacking them and constructing a respose packet (if needded).

        :param packet: the entire deconstructed packet
        :returns: a response packet after arp handling
        '''
        arp_request = packet.next_layer
        if arp_request.get_opcode() == ArpLayer.OP_IS_AT:
            return None
        response_packet = EthernetLayer() / ArpLayer()
        arp_header = response_packet.next_layer

        response_packet.set_dst(packet.get_src())
        response_packet.set_ether_type(ArpLayer.ETHR_TYPE)
        arp_header.set_opcode(ArpLayer.OP_IS_AT)

        if self.requested_interface == Router.NET1_NAME:
            response_packet.set_src(self.net1.get_mac())
            arp_header.set_src_mac(self.net1.get_mac())
            arp_header.set_src_ip(self.net1.get_ip())
        else:
            response_packet.set_src(self.net2.get_mac())
            arp_header.set_src_mac(self.net2.get_mac())
            arp_header.set_src_ip(self.net2.get_ip())

        arp_header.set_dest_mac(arp_request.get_src_mac())
        arp_header.set_dest_ip(arp_request.get_src_ip())

        self.arp_tbl[arp_request.get_src_ip()] = arp_request.get_src_mac()
        return response_packet

    def handle_ip(self, packet):
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
        
        elif self.INTERFACE_NAME2IP[self.requested_interface] == route_interface_ip:
            if dest_ip not in [self.net1.get_ip(), self.net2.get_ip()]:
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
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as raw_socket:
            while True:
                packet = raw_socket.recvfrom(Router.BUF_SIZE)
                packet_data, interface = packet
                self.requested_interface = interface[0]

                if self.requested_interface not in [self.net1.get_name(), self.net2.get_name()]:
                    self.requested_interface = None
                    continue

                layer_struct = EthernetLayer()
                layer_struct.deconstruct(packet_data)
                # Drop outcoming packets
                if MacAddress.mac2str(layer_struct.get_src()) in [Router.MAC_ROUTER_NET1, Router.MAC_ROUTER_NET2]:
                    continue
                self.handle_ether(layer_struct)


router = Router()
router.observe_traffic()
