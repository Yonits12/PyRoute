#!/usr/bin/env python3.7

import socket
import binascii
import struct
from pascy.l2 import *
from pascy.layer import *
from pascy.fields import *

HOST = '1.1.1.1'  # Standard loopback interface address (localhost)
PORT = 0        # Port to listen on (non-privileged ports are > 1023)

class Router:

    DEFAULT_IP = '0.0.0.0'
    ETH_TYPE_ARP = b'\x08\x06'
    ETH_TYPE_IPV4 = b'\x08\x00'
    MAC_ROUTER_NET1 = '024236e04043'
    MAC_ROUTER_NET2 = '024200338246'
    CLIENT1_MAC = '024201010102'
    CLIENT2_MAC = '024202020202'
    ARP_FORMAT = "2s2s1s1s2s6s4s6s4s"
    

    def __init__(self):
        arp_tbl = {}
        ip_tbl = {}

    # TODO stub
    def common_network(self, ip_1, ip_2):
        '''
        check if the 2 ips are from the same subnet of a router's interface and NOT the router's interface ip
        '''
        return False


    def print_arp(self, arp_detailed, ethernet_detailed, ethertype):
        print("****************_ETHERNET_FRAME_****************")
        print("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
        print("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
        print("Type:            ", binascii.hexlify(ethertype))
        print("************************************************")
        print("******************_ARP_HEADER_******************")
        print("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
        print("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
        print("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
        print("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
        print("Opcode:          ", binascii.hexlify(arp_detailed[4]))
        print("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
        print("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
        print("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
        print("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
        print("*************************************************\n")

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

    def handle_arp(self, arp_packet, ethernet_detailed, ethertype, interface):
        '''
        Handles ARP requests by unpacking them and constructing a respose packet (if needded).
        Prints the ARP packet contents.
        '''
        arp_header = arp_packet[0][14:42]       # ARP is 28 bytes payload
        arp_detailed = struct.unpack(Router.ARP_FORMAT, arp_header)
        self.print_arp(arp_detailed, ethernet_detailed, ethertype)
        
        if self.common_network(socket.inet_ntoa(arp_detailed[8]), socket.inet_ntoa(arp_detailed[6])):
            return None
        
        opcode = bytes.fromhex('0002')
        
        if interface == 'net1':
            source_mac = bytes.fromhex(Router.MAC_ROUTER_NET1)
            source_ip = bytes.fromhex('01010101')
        else:
            source_mac = bytes.fromhex(Router.MAC_ROUTER_NET2)
            source_ip = bytes.fromhex('02020201')

        new_ethernet_header = ethernet_detailed[1] + source_mac + ethertype
        arp_response = arp_header[:6] + opcode + source_mac + source_ip + arp_detailed[5] + arp_detailed[6]
        response_packet = new_ethernet_header + arp_response
        return response_packet

    def handle_ip(self, ip_packet, ethertype, ethernet_detailed):
        ip_header = ip_packet[0][14:34]       # IP is 20 bytes payload
        ip_detailed = struct.unpack("9s1s2s4s4s", ip_header)
        icmp_header = ip_packet[0][34:42]       # ICMP is 8 bytes payload
        icmp_detailed = struct.unpack("1s1s2s4s", icmp_header)
        self.print_ping(ethertype, ethernet_detailed, ip_detailed, icmp_detailed)
        
        if icmp_detailed[0] == b'08':
            new_ethernet_header = bytes.fromhex(Router.CLIENT1_MAC) + bytes.fromhex(Router.MAC_ROUTER_NET1) + ethertype
            ping_response = new_ethernet_header + ip_header + icmp_header 
            return ping_response
        elif icmp_detailed[0] == b'00':
            new_ethernet_header = bytes.fromhex(Router.CLIENT2_MAC) + bytes.fromhex(Router.MAC_ROUTER_NET2) + ethertype
            ping_response = new_ethernet_header + ip_header + icmp_header 
            return ping_response
        else: 
            return None

    def create_ip_packet(self, request_packet):
        return request_packet

    def observe_traffic(self):
        '''
        Gets incoming packets from net1 net2 interfaces and handles them.
        '''
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as rawSocket:
            while True:
                packet = rawSocket.recvfrom(4096)
                (_, interface) = packet
                if (interface[0] != 'net1') and (interface[0] != 'net2'):
                    continue
                # ethernet_unpacking
                interface = interface[0]
                ethernet_header = packet[0][0:14]       # ARP is 14 bytes payload
                ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
                ethertype = ethernet_detailed[2]
                print("\nethertype\n", ethertype)
                
                if ethertype == Router.ETH_TYPE_ARP:
                    arp_response_packet = self.handle_arp(packet, ethernet_detailed, ethertype, interface)
                    if arp_response_packet is None:
                        continue
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as arp_socket:
                        arp_socket.bind(("net2", 0))    # TODO bind to correct interface
                        arp_socket.send(arp_response_packet)

                elif ethertype == Router.ETH_TYPE_IPV4:
                    ip_response_packet = self.handle_ip(packet, ethertype, ethernet_detailed)
                    if ip_response_packet is None:
                        continue
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as arp_socket:
                        arp_socket.bind(("net1", 0))    # TODO bind to correct interface
                        arp_socket.send(ip_response_packet)
                


router_1 = Router()
router_1.observe_traffic()