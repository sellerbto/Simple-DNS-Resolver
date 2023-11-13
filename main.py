import socket
import binascii
import asyncio
from enums import *


root_servers = ("a.root-servers.net", "b.root-servers.net", "c.root-servers.net", "d.root-servers.net",
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

async def get_answer(dns_server, request):
    reader, writer = asyncio.open_connection(dns_server, 53)
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    writer.write(request)
    await writer.drain()
    await asyncio.sleep(0.2)
    response = DnsMessage(await reader.read(4096))
    if len(response.answers) != 0:
        return response
    for i in response.authorities:
        print(i)


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    try:
        client_request = await client_reader.read(4096)
        for root in root_servers:
            answer = await get_answer(root, client_request)
            if answer:
                break
        client_writer.write(answer.in_bytes_response)
        await client_writer.drain()
    except AttributeError as e:
        print(e)
    except TypeError as e:
        print(e)
    finally:
        client_writer.close()







async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 53)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

