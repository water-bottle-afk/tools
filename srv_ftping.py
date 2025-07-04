import os.path

# not completed

from scapy.all import *
from scapy.layers.inet import ICMP, IP


def manage_server():

    lst = sniff(count=1, iface=iface,filter="icmp")
    print(lst)

if __name__ == "__main__":
    manage_server()
