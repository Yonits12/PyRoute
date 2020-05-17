#!/usr/bin/env python3.7

import socket
import binascii
import struct
from pascy.l2 import *
from pascy.l3 import *
from pascy.l4 import *
from pascy.layer import *
from pascy.fields import *


class RoutingTuple:
    
    def __init__(self, network_dst, netmask, interface):
        self.network_dst = network_dst
        self.netmask = netmask
        self.interface = interface


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
    NET1_IP = '1.1.1.1'
    NET2_IP = '2.2.2.1'
    MASK_24_SUBNET = '255.255.255.0'
    ETH_TYPE_ARP = b'\x08\x06'
    ETH_TYPE_IPV4 = b'\x08\x00'

    MAC_ROUTER_NET1 = '02:42:36:E0:40:43'
    MAC_ROUTER_NET2 = '02:42:00:33:82:46'
    CLIENT1_MAC = '02:42:01:01:01:02'
    CLIENT2_MAC = '02:42:02:02:02:02'

    INTERFACE_MAPPER = {MAC_ROUTER_NET1: 'net1',
                        MAC_ROUTER_NET2: 'net2'}

    ROUTING_TABLE = {(DEFAULT, DEFAULT, None),
                    ('1.1.1.0', MASK_24_SUBNET, NET1_IP),
                    ('2.2.2.0', MASK_24_SUBNET, NET2_IP)}

    BUF_SIZE = 2048


    def __init__(self):
        self.net1 = Interface(Router.NET1_IP, Router.MAC_ROUTER_NET1, 'net1')
        self.net2 = Interface(Router.NET2_IP, Router.MAC_ROUTER_NET2, 'net2')
        self.requested_interface = None
        self.arp_tbl = {}
        self.ip_tbl = {}

    # TODO stub
    def common_network(self, ip_1, ip_2):
        '''
        check if the 2 ips are from the same subnet of a router's interface and NOT the router's interface ip
        '''
        return False

    def print_ping(self, ethertype, ethernet_detailed, ip_detailed, icmp_detailed):
        print("****************_ETHERNET_FRAME_****************")
        print("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
        print("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
        print("Type:            ", binascii.hexlify(ethertype))
        print("************************************************")
        print("******************_IP_HEADER_******************")
        print("Version...TTL:   ", binascii.hexlify(ip_detailed[0]))
        print("Protocol type:   ", binascii.hexlify(ip_detailed[1]))
        print("Checksum:        ", binascii.hexlify(ip_detailed[2]))
        print("Source IP:       ", socket.inet_ntoa(ip_detailed[3]))
        print("Dest IP:         ", socket.inet_ntoa(ip_detailed[4]))
        print("*************************************************\n")
        print("******************_ICMP_HEADER_******************")
        print("Type:      ", binascii.hexlify(icmp_detailed[0]))
        print("Code:      ", binascii.hexlify(icmp_detailed[1]))
        print("Checksum:  ", binascii.hexlify(icmp_detailed[2]))
        print("Rest:      ", binascii.hexlify(icmp_detailed[3]))
        print("*************************************************\n")

    def handle_ether(self, ether_struct):
         # ethernet handling
        if ether_struct.get_ether_type() == ArpLayer.ETHR_TYPE:
            arp_response_packet = self.handle_arp(ether_struct)
            if arp_response_packet is None:
                return
            arp_response_packet.display()       #DEBUG
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as arp_socket:
                arp_socket.bind((self.requested_interface, 0))
                arp_socket.send(arp_response_packet.build())

        elif ether_struct.get_ether_type() == IPv4Layer.ETHR_TYPE:
            ip_response_packet = self.handle_ip(ether_struct)
            if ip_response_packet is None:
                return
            print("___________  IP_RESPONSE:  __________")
            ip_response_packet.display()    #DEBUG
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as ip_socket:
                src_mac = ip_response_packet.get_src()
                src_mac = MacAddress.mac2str(src_mac)
                name = self.INTERFACE_MAPPER[src_mac]
                ip_socket.bind((name, 0))    # TODO bind to correct interface
                ip_socket.send(ip_response_packet.build())

    def handle_arp(self, packet):
        '''
        Handles ARP requests by unpacking them and constructing a respose packet (if needded).
        Prints the ARP packet contents.
        '''
        arp_request = packet.next_layer
        if arp_request.get_opcode() == ArpLayer.OP_IS_AT:
            return None
        response_packet = EthernetLayer() / ArpLayer()
        arp_header = response_packet.next_layer
        
        # if self.common_network(socket.inet_ntoa(arp_request.get_src_ip()), socket.inet_ntoa(arp_request.get_dest_ip())):
        #     return None
        
        response_packet.set_dst(packet.get_src())
        response_packet.set_ether_type(ArpLayer.ETHR_TYPE)

        arp_header.set_opcode(ArpLayer.OP_IS_AT)
        if self.requested_interface == 'net1':
            response_packet.set_src(self.net1.get_mac())
            arp_header.set_src_mac(self.net1.get_mac())
            arp_header.set_src_ip(self.net1.get_ip())
        else:       #TODO so redunant to else for just net2... dict it
            response_packet.set_src(self.net2.get_mac())
            arp_header.set_src_mac(self.net2.get_mac())
            arp_header.set_src_ip(self.net2.get_ip())

        arp_header.set_dest_mac(arp_request.get_src_mac())
        arp_header.set_dest_ip(arp_request.get_src_ip())

        return response_packet

    def handle_icmp(self, packet):
        ether = packet
        ip_layer = packet.next_layer
        dest_ip = socket.inet_ntoa(ip_layer.get_dest_ip())
        if dest_ip == '2.2.2.2':
            ether.set_dst(Router.CLIENT2_MAC)
            ether.set_src(Router.MAC_ROUTER_NET2)
        elif dest_ip == '1.1.1.2':
            ether.set_dst(Router.CLIENT1_MAC)
            ether.set_src(Router.MAC_ROUTER_NET1)
        return packet
        

    def handle_ip(self, packet):
        ip_request = packet.next_layer
        if ip_request.get_protocol() == ICMPLayer.PROTOCOL_ID:
            return self.handle_icmp(packet)
        else:
            # not implemented yet
            response_packet = EthernetLayer() / IPv4Layer()
            return None

    def create_ip_packet(self, request_packet):
        return request_packet

    def observe_traffic(self):
        '''
        Gets incoming packets from net1 net2 interfaces and handles them.
        '''
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as raw_socket:
            while True:
                packet = raw_socket.recvfrom(Router.BUF_SIZE)
                packet_data, interface = packet
                self.requested_interface = interface[0]
                
                # print("packet of type: ", interface[1])
                if self.requested_interface not in ['net1', 'net2', 'veth931e985', 'veth37b30f9']:
                    self.requested_interface = None
                    continue
                print("from interface: ", interface[0], " at leg: ", MacAddress.mac2str(interface[4]))
                layer_struct = EthernetLayer()
                layer_struct.deconstruct(packet_data)
                if MacAddress.mac2str(layer_struct.get_src()) in [Router.MAC_ROUTER_NET1, Router.MAC_ROUTER_NET2]:
                    continue
                print("____________ deconstruct _____________") # DEBUG
                layer_struct.display()      # DEBUG
                self.handle_ether(layer_struct)


router = Router()
router.observe_traffic()
