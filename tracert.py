__author__ = "Nadav"
from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1
import sys


def tracert(url):
    lst = []
    ttl = 1
    max_hops = 30

    print(f"Trace routing {url}....", end="\n")

    try:
        tmp = IP(dst=url)  # "avoiding" from looking for the url's ip
        while tmp[IP].dst not in lst:
            if ttl > max_hops:
                break
            p = IP(ttl=ttl, dst=url) / ICMP()
            send_time = datetime.now()
            x = sr1(p, verbose=False, timeout=3)
            recv_time = datetime.now()
            # im assuming that the delta time is not gonna be more than one sec for successful answer. so:
            del_time = (recv_time - send_time) % timedelta(seconds=1)
            if x and x[IP].src not in lst:
                lst.append(x[IP].src)
                # visual adjustments
                length = len(str(lst[-1]))
                st_to_append_ip = (15 - length) * " "
                st_to_append_hop = "  "
                if ttl >= 10:
                    st_to_append_hop = " "

                print(f"Hop {ttl}: {st_to_append_hop} {lst[-1]} {st_to_append_ip} {del_time.microseconds // 1000} ms")
            else:
                print(f"Hop {ttl}: \t\t *****")
            ttl += 1
            time.sleep(1)

        found = tmp[IP].dst in lst
        if found:
            print(f"Tracing complete. Reached Destination {url}!")
        else:
            print(f"Couldn't Reach Destination {url}!")
    except:
        print(f"Unable to resolve target system name {url}.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        tracert(sys.argv[1])
    else:
        print("No url given.")
        url = input("Url to check: -->")
        tracert(url)
