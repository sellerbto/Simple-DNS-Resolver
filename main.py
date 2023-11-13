import socket
import binascii
from enums import *


class ByteStream:
    def __init__(self, response: bytes):
        self._bytes = response
        self.index = 0

    def __getitem__(self, index):
        if isinstance(index, slice):
            self.index = index.stop
            return self._bytes[index.start:index.stop]
        self.index = index + 1
        return self._bytes[index]

    def next_byte(self, slice=1):
        return self[self.index:self.index + slice]


class A:
    def __init__(self, response: ByteStream):
        self.ip = [response.next_byte(), response.next_byte(), response.next_byte(), response.next_byte()]

    def __str__(self):
        return str.join('.', [str(int.from_bytes(i)) for i in self.ip])


class NS:
    def __init__(self, response):
        self.name = Parse.host_name(response)


class Record:
    def __init__(self, response: ByteStream):
        self.host_name = Parse.host_name(response)
        self.atype = DnsType(int.from_bytes((response.next_byte(slice=2))))
        self.aclass = DnsClass(int.from_bytes((response.next_byte(slice=2))))
        self.ttl = int.from_bytes(response.next_byte(slice=4))
        self.rdlength = int.from_bytes(response.next_byte(slice=2))
        if self.atype == DnsType.A:
            self.rdata = A(response)
        elif self.atype == DnsType.NS:
            self.rdata = NS(response)
        else:
            raise TypeError


class Header:
    def __init__(self, response: ByteStream):
        self.ID = response.next_byte(slice=2)
        self._FromQR_toRCODE = response.next_byte(slice=2)
        self._QDCount = response.next_byte(slice=2)
        self._ANCount = response.next_byte(slice=2)
        self._NSCount = response.next_byte(slice=2)
        self._ARCount = response.next_byte(slice=2)

    @property
    def answers_count(self):
        return int.from_bytes(self._ANCount)

    @property
    def ns_count(self):
        return int.from_bytes(self._NSCount)

    @property
    def ar_count(self):
        return int.from_bytes(self._NSCount)

    @property
    def qd_count(self):
        return int.from_bytes(self._QDCount)


class Question:
    def __init__(self, response: ByteStream):
        self.host_name = Parse.host_name(response)
        self.qtype = DnsType(int.from_bytes(response.next_byte(slice=2)))
        self.qclass = DnsClass(int.from_bytes(response.next_byte(slice=2)))


class Answer(Record):
    def __init__(self, response: ByteStream):
        super().__init__(response)


class Authority(Record):
    def __init__(self, response: ByteStream):
        super().__init__(response)


class Additional(Record):
    def __init__(self, response: ByteStream):
        super().__init__(response)


def send_dns_request(address, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message, (address, port))
        data = sock.recv(8192)
        # return binascii.hexlify(data).decode("utf-8")
        return data
    except:
        sock.close()


class DnsRequest:
    def __init__(self, domain):
        self._header = self._make_header()
        self._question = self._make_question(domain)

    @staticmethod
    def _make_question(domain: str):
        labels = domain.split(".")
        question = []
        for label in labels:
            label_length = len(label).to_bytes()
            binary_label = label.encode('ascii')
            question.append(label_length)
            question.append(binary_label)
        question.append(binascii.unhexlify("00"))
        QTYPE = binascii.unhexlify("0001")  # A - запись
        QCLASS = binascii.unhexlify("0001")  # IN - интернет
        question.append(QTYPE)
        question.append(QCLASS)
        return b''.join(question)

    @staticmethod
    def _make_header():
        id = binascii.unhexlify("AAAA")
        fromQR_toRCODE = binascii.unhexlify("0000")
        QDCOUNT = binascii.unhexlify("0001")
        ANCOUNT = binascii.unhexlify("0000")
        NSCOUNT = binascii.unhexlify("0000")
        ARCOUNT = binascii.unhexlify("0000")
        return b''.join([id, fromQR_toRCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT])

    def build(self):
        return b''.join([self._header, self._question])


class Parse:
    @staticmethod
    def host_name(response: ByteStream):
        host_name = []
        while True:
            label = []
            label_length = int.from_bytes(response.next_byte())
            if label_length == 0:
                break
            if label_length >= 192:
                response.index -= 1
                offset_index = int.from_bytes(response.next_byte(slice=2)) & 16383
                old_index = response.index
                response.index = offset_index
                offset_host_name = Parse.host_name(response)
                response.index = old_index
                known_part = str.join('.', host_name)
                if known_part == "":
                    return offset_host_name
                else:
                    return f"{known_part}.{offset_host_name}"
            for i in range(label_length):
                label.append(chr(int.from_bytes(response.next_byte())))
            host_name.append("".join(label))
        return str.join(".", host_name)


class DnsResponse:
    def __init__(self, response: bytes):
        response = ByteStream(response)
        self.header = Header(response)
        self.questions = []
        for i in range(self.header.qd_count):
            self.questions.append(Question(response))
        self.answers = []
        for i in range(self.header.answers_count):
            self.answers.append(Answer(response))
        self.authorities = []
        for i in range(self.header.ns_count):
            self.authorities.append(Authority(response))
        self.additionals = []
        for i in range(self.header.ar_count):
            self.additionals.append(Additional(response))


message = DnsRequest("yandex.ru").build()
response = send_dns_request("199.9.14.201", 53,
                            message)

a = DnsResponse(response)
# message2 = binascii.unhexlify("AA AA 01 00 00 01 00 00 00 00 00 00 " \
# "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01".replace(" ", "").replace("\n", ""))
# print(send_dns_request("199.9.14.201", 53,
#                        message))
# удобно использовать hex потому что hex = 1 byte

'''
request-template in hex:
AA AA # 16 bit ID
0 # QR zero means query
1 # 
00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
'''
