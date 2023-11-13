from enum import Enum


class DnsClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4

    @classmethod
    def __missing__(cls, key):
        raise AttributeError("Unknown Dns Type!")


class DnsType(Enum):
    A = 1  # IPv4
    AAAA = 28  # IPv6

    @classmethod
    def __missing__(cls, key):
        raise AttributeError("Unknown Dns Type!")
