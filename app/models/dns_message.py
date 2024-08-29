from . import dns_message_header

class DNSMessage:
    def __init__(self):
        self.header: DNSMessageHeader = DNSMessageHeader()

    def get_message_bytes(self) -> bytes:
        message_bytes = b''
        message_bytes += self.header.get_header_bytes()

        return message_bytes