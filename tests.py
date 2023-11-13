import asyncio
import binascii
import unittest
import main



full = main.ByteStream(b"\xaa\xaa\x80\x00\x00\x01\x00\x00\x00\x05\x00\n\x06yandex\x02ru\x00\x00\x01\x00\x01\xc0\x13\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x10\x01d\x03dns\x04ripn\x03net\x00\xc0\x13\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01f\xc0)\xc0\x13\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01a\xc0)\xc0\x13\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01b\xc0)\xc0\x13\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01e\xc0)\xc0C\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc1\xe8\x9c\x11\xc0s\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc1\xe8\x8e\x11\xc0'\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc2\xbe|\x11\xc0c\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc2U\xfc>\xc0S\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc1\xe8\x80\x06\xc0C\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x06x\x00\x14\x00\x00\x01\x93\x022\x01V\x00\x17\xc0s\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x06x\x00\x15\x00\x00\x01\x93\x022\x01B\x00\x17\xc0'\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x06x\x00\x18\x00\x00\x01\x94\x01\x90\x01$\x00\x17\xc0c\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x06x\x00\x16\x00\x00\x01\x94\x00\x85\x02R\x00b\xc0S\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x06x\x00\x17\x00\x00\x01\x93\x022\x01(\x00\x06")


header = main.ByteStream(full[0:12])
question = main.ByteStream(full[12:27])

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

class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test(self):
        loop = asyncio.get_event_loop()
        loop.set_debug(True)
        request = main.DnsMessage(DnsRequest("yandex.ru").build())
        result = loop.run_until_complete(await main.get_answer("199.9.14.201", request))
        loop.close()
        print(result)

class Tests(unittest.TestCase):

    def create_bytestream(self, byte):
        return main.ByteStream(byte)

    def test_host_name_parser_simple_cases(self):
        test_cases = [(b"\x03one\x03two\x05three\x04four\x00", "one.two.three.four"), (b"\x03192\x03168\x011\x011\x00", "192.168.1.1")]
        for test in test_cases:
            byte_stream = self.create_bytestream(test[0])
            self.assertEqual(main.Parse.host_name(byte_stream), test[1])

    def test_host_name_parser_with_offset(self):
        pass


    def test_parse_question(self):
        byte_stream = self.create_bytestream(full[12:27])
        q = main.Question(byte_stream)
        self.assertEqual(q.host_name, "yandex.ru")
        self.assertEqual(q.qtype, main.DnsType.A)
        self.assertEqual(q.qclass, main.DnsClass.IN)

    def test_parse_header(self):
        byte_stream = self.create_bytestream(full[0:12])
        h = main.Header(byte_stream)
        self.assertEqual(h.qd_count, 1)
        self.assertEqual(h.ns_count, 5)
        self.assertEqual(h.ar_count, 5)
        self.assertEqual(h.answers_count, 0)

    def test_2(self):
        byte_stream = self.create_bytestream(full)
        byte_stream.index = 27
        a = main.Answer(byte_stream)
        print(a)