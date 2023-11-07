import socket
import binascii

def send_dns_request(address, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = message.replace(" ", "").replace("\n", "")
    try:
        sock.sendto(binascii.unhexlify(message), (address, port))
        data = sock.recv(4096)
        return binascii.hexlify(data).decode("utf-8")
    except:
        sock.close()

class DnsRequest:
    def __init__(self, id, recursion):
        self.id = id
        self.recursion = recursion

    def build(self):
        return binascii.unhexlify(f"{id}")
        binascii.



print(send_dns_request("8.8.8.8", 53,
                                  "AA AA 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"))

'''
request-template in hex:
AA AA # 16 bit ID
0 # QR zero means query
1 # 
00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
'''