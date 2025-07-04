from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

author = "Nadav"
import sys
import scapy
from scapy.all import *

DNS_SERVER_IP = "8.8.8.8"
DNS_CONST_PORT = 53
SOURCE_PORT = 24501


def create_packet(dns_query_qname, dns_query_qtype):
    p = (IP(dst=DNS_SERVER_IP) / UDP(sport=SOURCE_PORT, dport=DNS_CONST_PORT) / DNS(qdcount=1, rd=1))
    p[DNSQR].qname = dns_query_qname  # getting over the scapy cache
    p[DNSQR].qtype = dns_query_qtype  # getting over the scapy cache
    return p


def extract_from_packet(ans_packet, name, addresses, aliases):
    if ans_packet[DNS].an == []:
        return name, addresses, aliases

    for ans in ans_packet[DNS].an:
        if ans.type == 1 or ans.type == 28:  # add addersses for ipv4, ipv6
            if ans.rdata not in addresses:
                addresses.append(ans.rdata)

            if ans.rrname.decode() != name:  # add name
                name = ans.rrname.decode()

        elif ans.type == 5:
            if ans.rrname == ans_packet[DNS].qd.qname:
                # add aliases
                if ans.rrname.decode() not in aliases:
                    aliases.append(ans.rrname.decode())

                if ans.rdata.decode() not in aliases:
                    aliases.append(ans.rdata.decode())

            # add addresses
            if ans.rrname.decode() == name:
                if ans.rdata.decode() not in addresses:
                    addresses.append(ans.rdata.decode())
    #
    # print(f"Names: {names}")
    # print(f"addresses: {addresses}")
    # print(f"aliases: {aliases}")

    return name, addresses, aliases


def extract_from_packets(ans1, ans2, ans3, ans4):
    name = ""
    addresses = []
    aliases = []

    name, addresses, aliases = extract_from_packet(ans1, name, addresses, aliases)
    name, addresses, aliases = extract_from_packet(ans2, name, addresses, aliases)
    name, addresses, aliases = extract_from_packet(ans3, name, addresses, aliases)
    name, addresses, aliases = extract_from_packet(ans4, name, addresses, aliases)
    return name, addresses, aliases


def get_returned_packet(packet_to_send, num=0):
    if num == 5:
        return None
    ans1 = sr1(packet_to_send, timeout=5, verbose=False)  # do it clean
    if ans1 is None:
        return get_returned_packet(packet_to_send,num+1)
    return ans1


def get_data_about_url(url):
    """

    :param url: url
    :return: returns: name, addresses, aliases
    """

    url_to_get = url + ".home"
    p = create_packet(url_to_get, 1)  #type A - ipv4
    ans1 = get_returned_packet(p)

    url_to_get = url + ".home"
    p = create_packet(url_to_get, 28)  # typw AAAA - ipv6
    ans2 = get_returned_packet(p)

    url_to_get = url
    p = create_packet(url_to_get, 1)  # type A - ipv4
    ans3 = get_returned_packet(p)

    url_to_get = url
    p = create_packet(url_to_get, 28)  # typw AAAA - ipv6
    ans4 = get_returned_packet(p)

    return extract_from_packets(ans1, ans2, ans3, ans4)


def get_domain(pkt):
    # assuming a server has only one name
    answers = pkt[DNS].an
    return answers.rdata.decode()


def get_server_domain_by_ip(DNS_SERVER_IP):
    """

    :param DNS_SERVER_IP:
    :return: the name of the server by ip (PTR- domain name pointer)
    """
    url = DNS_SERVER_IP + ".in-addr.arpa"
    p = create_packet(url, 12)

    x = sr1(p, timeout=5, verbose=False)  # do it clean
    return get_domain(x)


def print_data(name, addresses, alises):
    print("Non-authoritative answer:")
    print(f"Name:  {name}")
    if len(addresses) > 0:
        print(f"Addresses:  {addresses[0]}")
        for i in range(1, len(addresses)):
            print(f"          {addresses[i]}")
    if len(alises) > 0:
        print(f"Aliases:  {alises[0]}")
        for i in range(1, len(alises)):
            print(f"          {alises[i]}")
    print('')


def main():
    global DNS_SERVER_IP
    url = ""
    if len(sys.argv) > 1:
        url = sys.argv[1]
    if len(sys.argv) > 2:
        DNS_SERVER_IP = sys.argv[2]
    while True:
        if url == '':
            url = input(">")

        server_name = get_server_domain_by_ip(DNS_SERVER_IP)
        print(f"Server:  {server_name}")
        print(f"Address:  {DNS_SERVER_IP} \n")

        try:
            name, addresses, aliases = get_data_about_url(url)
            if name != '':
                print_data(name, addresses, aliases)
            else:
                print(f"*** can't find {url}: Non-existent domain")
        except:
            print(f"*** can't find {url}: Non-existent domain")
        url = ''


if __name__ == "__main__":
    main()
