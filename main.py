import socket
import binascii
import asyncio
import asyncio_dgram
from enums import *


root_servers = ("198.41.0.4", "199.9.14.201", "c.root-servers.net", "d.root-servers.net",
                "e.root-servers.net", "g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
                "j.root-servers.net", "k.root-servers.net", "l.root-servers.net", "m.root-servers.net",)


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

class AAAA:
    def __init__(self, response: ByteStream):
        self.ip = ""
        for i in range(0, 8):
            self.ip += str(int.from_bytes(response.next_byte(slice=2)))


class A:
    def __init__(self, response: ByteStream):
        self.ip = [response.next_byte(), response.next_byte(), response.next_byte(), response.next_byte()]

    def __str__(self):
        return str.join('.', [str(int.from_bytes(i)) for i in self.ip])


class NS:
    def __init__(self, response):
        self.ip = Parse.host_name(response)


class Record:
    def __init__(self, response: ByteStream):
        self.host_name = Parse.host_name(response)
        self.atype = int.from_bytes((response.next_byte(slice=2)))
        self.aclass = int.from_bytes((response.next_byte(slice=2)))
        self.ttl = int.from_bytes(response.next_byte(slice=4))
        self.rdlength = int.from_bytes(response.next_byte(slice=2))
        if self.atype == DnsType.A.value:
            self.rdata = A(response)
        elif self.atype == DnsType.NS.value:
            self.rdata = NS(response)
        elif self.atype == DnsType.AAAA.value:
            self.rdata = AAAA(response)


class Header:
    def __init__(self, response: ByteStream):
        self.id = response.next_byte(slice=2)
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


class DnsMessage:
    def __init__(self, response: bytes):
        self.in_bytes_response = response
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

async def get_answer(dns_server, request: DnsMessage):
    try:
        conn = await asyncio_dgram.connect((dns_server, 53))
        await conn.send(request.in_bytes_response)
        await asyncio.sleep(0.2)
        response, addr = await conn.recv()
        response = DnsMessage(response)
        if len(response.answers) != 0:
            return response
        for i in response.authorities:
            if i.atype != DnsType.NS.value:
                continue
            conn.close()
            authority_address = await get_authority_address(response, i, dns_server)
            return await get_answer(authority_address, request)
        return response
    except Exception as e:
        print(e)




async def get_authority_address(message: DnsMessage, authority: Authority, server: (str, int)):
    for add in message.additionals:
        if add.host_name == authority.rdata.ip and add.atype == DnsType.A.value:
            return str(add.rdata)
    return (await handle_client(DnsRequest(authority.rdata.ip).build())).answers[0].host_name





async def handle_client(client_request):
    try:
        client_request = DnsMessage(client_request)
        for root in root_servers:
            answer = await get_answer(root, client_request)
            if answer:
                return answer
        return None
    except AttributeError as e:
        print(e)
    except TypeError as e:
        print(e)


async def handle_client1(data, remote_addr, server):
   print("got")
   answer = await handle_client(data)
   await server.send(answer.in_bytes_response, remote_addr)

async def main():
   server = await asyncio_dgram.bind(("0.0.0.0", 1337))
   while True:
       data, remote_addr = await server.recv()
       asyncio.create_task(handle_client1(data, remote_addr, server))

if __name__ == "__main__":
   loop = asyncio.get_event_loop()
   loop.set_debug(True)
   loop.run_until_complete(main())
   loop.run_forever()

