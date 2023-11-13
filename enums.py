from enum import Enum


class DnsClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4


    @classmethod
    def __missing__(cls, key):
        raise AttributeError("Unknown Dns Class!")


class DnsType(Enum):
    A = 1
    AAAA = 28
    AXFR = 252
    CNAME = 5
    HINFO = 13
    MX = 15
    NS = 2
    PTR = 12,
    ANY = 255
    EMPTY = 41

    @classmethod
    def __missing__(cls, key):
        raise AttributeError("Unknown Dns Type!")
