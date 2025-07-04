__author__ = "Nadav"

import threading
import socket
import struct

"""
dns server.
"""

dict_of_addresses = {"www.google.com": "157.240.22.35", # for instance typing google would get the facebook's ip
                     "www.freeVBUCKS.co.il": "66.67.68.69",
                     "www.mikmak.co.il": "22.22.2.2"}


def log(dir, lst_of_data, data=''):
    # 1 = got, 2 = sent
    lst_recv = ["tid", "flags", "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT", "domain", "q_type", "q_class"]
    lst_send = ["response_domain","answer_type", "answer_class", "TTL", "ip_length", "ip"]

    if dir == '1':
        print("Data is:")
        print(data)
        print("Server GOT:")
        for item1, item2 in zip(lst_of_data, lst_recv):
            try:
                num = int.from_bytes(item1, byteorder='big')
                print(item2 + "  : " + str(num))
            except:
                print(item2 + "  : " + str(item1))
    else:
        print("Server SENT:")
        for item in lst_send:
            lst_recv.append(item)

        for item1, item2 in zip(lst_of_data, lst_recv):
            try:
                num = int.from_bytes(item1, byteorder='big')
                print(item2 + "  : " + str(num))
            except:
                print(item2 + "  : " + str(item1))

    print("_______________")


def ip_in_bytes(ip):
    st = ''
    lst = ip.split('.')
    byte_rep = bytes([int(item) for item in lst])  # Convert to raw bytes
    return byte_rep


def extract_url(domain_name):
    idx = 0
    lst = []
    while True:
        try:
            amount = int(domain_name[idx])
            tmp_str = ''
            for i in range(amount):
                tmp_str += chr(domain_name[i + idx + 1])
            idx += amount + 1
            lst.append(tmp_str)

        except Exception as e:
            break
    return ".".join(lst[:-1])


def parse(data):
    #unsigned 2 bytes = 16 bits = H
    # ! for network bytes
    #extractes header
    id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
    rest_of_data = data[12:-4]
    domain = extract_url(rest_of_data)
    q_type = data[-4:-2]
    q_class = data[-2:]
    lst = [id, flags, qd_count, an_count, ns_count, ar_count, domain, q_type, q_class]
    log('1', lst, data)
    return lst


def build_answer(data, lst):
    try:
        # בדיקה אם q_type != A (1)
        if lst[7] != b'\x00\x01':
            return build_empty_response(data, lst)

        ip = dict_of_addresses[lst[6]]
        answer_ip = ip_in_bytes(ip)

        lst_of_answer = []
        lst_of_answer.append(lst[0].to_bytes(2, "big"))  # ID
        lst_of_answer.append(b"\x81\x80")  # Flags
        lst_of_answer.append(b"\x00\x01")  # QDCOUNT
        lst_of_answer.append(b"\x00\x01")  # ANCOUNT
        lst_of_answer.append(b"\x00\x00")  # NSCOUNT
        lst_of_answer.append(b"\x00\x00")  # ARCOUNT
        lst_of_answer.append(data[12:-4])  # Domain (raw)
        lst_of_answer.append(b"\x00\x01")  # QTYPE
        lst_of_answer.append(b"\x00\x01")  # QCLASS
        lst_of_answer.append(b"\xc0\x0c")  # Name pointer
        lst_of_answer.append(b"\x00\x01")  # TYPE = A
        lst_of_answer.append(b"\x00\x01")  # CLASS = IN
        lst_of_answer.append(b"\x00\x00\x00\x04")  # TTL
        lst_of_answer.append(b"\x00\x04")  # RDLENGTH
        answer = b''.join(lst_of_answer) + answer_ip
        lst_of_answer.append(ip)
        lst_of_answer[6] = extract_url(lst_of_answer[6])
        log('2', lst_of_answer)
        return answer
    except:
        return build_empty_response(data, lst)

def build_empty_response(data, lst):
    tid = lst[0].to_bytes(2, "big")
    flags = b'\x81\x80'  
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'  # no answers
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    question = data[12:]  # the original query
    response = tid + flags + qdcount + ancount + nscount + arcount + question
    return response

def handle_recv(data, addr, srv_socket):
    lst = parse(data)
    srv_socket.sendto(build_answer(data, lst),addr)


def main():
    ip = "0.0.0.0"
    port = 53
    srv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_socket.bind((ip, port))
    srv_socket.settimeout(30)

    while True:
        data, addr = srv_socket.recvfrom(1024)  # buffer size is 1024 bytes
        t = threading.Thread(target=handle_recv, args=(data,addr,srv_socket))
        t.start()

if __name__ == "__main__":
    main()
