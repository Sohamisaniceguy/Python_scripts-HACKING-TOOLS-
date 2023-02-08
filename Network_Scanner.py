#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_args():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Scan Range of IP or specific IP in a network")
    option,arg=parser.parse_args()
    if not option.target:
        parser.error("[-]Please specify a target , use --help for more info.")
    return option

def scan(ip):
    # scapy.arping(ip)

    arp_request= scapy.ARP(pdst=ip)  # ARP request
    # arp_request.pdst=ip

    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  #Braodcast the request

    arp_request_broadcast=broadcast/arp_request #Combination of 2 packet

    answered,unanswered =scapy.srp(arp_request_broadcast,verbose=False,timeout=1)  ##gives back 2 values(LIST)
    clients_list=[]
    for i in answered:
        client_dict={"ip":i[1].psrc,"mac":i[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
    # print(arp_request.summary())
    # print(broadcast.summary())
    # print(arp_request_broadcast.show())
    # print(answerd.summary())
def result(result_list):
    print("IP\t\t\t\tMAC ADDRESS \n--------------------------------------------------")
 #print the elements in the lists one by one
    for client in result_list:
        # print(i[1].show()) #all the values in the 2nd half
        print(client["ip"] + "\t\t" + client["mac"])
        print("-----------------------------------------------------")

option=get_args()
scan_result=scan(option.target)
result(scan_result)