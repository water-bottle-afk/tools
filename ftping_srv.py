import os.path

from scapy.all import *
from scapy.layers.inet import ICMP, IP

server_ip = "127.0.0.1" # to change
# server_port = 2020

def send_packet(bdata):

    request_packet = IP(dst=server_ip) / ICMP(type="echo-request") / bdata
    x = sr(request_packet, verbose=False, timeout=3)
    for item in x:
        item.show()
        if b"ACK" in item[Raw]:
            return True
    return False


def sending_file(path):
    try:
        with open(path,"rb") as file:
            bdata = file.read(500)
            print(bdata)
            server_got_msg = send_packet(bdata)
            while server_got_msg:
                bdata = file.read(500)
                print(bdata)
                server_got_msg = send_packet(bdata)


    except OSError as e:
        print(f"OS ERROR {e}")
    except Exception as e:
        print(f"ERROR {e}")

if __name__ == "__main__":
    path = input("Enter path >")
    path = os.path.abspath(path)
    sending_file(path)
