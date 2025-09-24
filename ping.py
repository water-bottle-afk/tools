from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1
import sys
# ping

if len(sys.argv)<2:
    ip_to_send = input("Enter IP")
    pkt = IP(dst="www.facebook.com")/ICMP()
else:
    pkt = IP(dst=sys.argv[1])/ICMP()

count_recvd = 0
lst_of_pkts = []
for i in range(int(sys.argv[2])):
    new_pkt = pkt/Raw(load=str(i+1))
    lst_of_pkts.append(new_pkt)

print(f"Sended {sys.argv[2]} packets.")

answers,_ = sr(lst_of_pkts, verbose = False, timeout=5)
if answers:
    count_recvd+=len(answers)
    print(f"Recived {count_recvd}")
else:
    print("RECVED NONE")


