import socket



class DNSMessage:
    def __init__(self):
        self.header: DNSMessageHeader = DNSMessageHeader()

    def get_message_bytes(self) -> bytes:
        message_bytes = b''
        message_bytes += self.header.get_header_bytes()

        return message_bytes

class DNSMessageHeader:
    """This is the DNS message header class"""

    '''
        This is the constructor mmethod of a class in Python.
        When a class defines an __init__ method, class instantiation automatically invokes __init__()
        for the newly created object, meaning that with __init__ we customize our newly instantiated
        object's intial state.
    '''
    def __init__(self):
        # These are instance variables since they are defined inside the constructor of the class,
        # instance variables are for data that is unique to each class instance.
        self.packet_id = 1234
        # Indicates if the DNS message is a query or a response to a query (1 is for response).
        self.query_or_response_indicator = 1
        self.operation_code = 0
        # Specifies if the responding server "owns" the domain being queried, i.e., it's authoritative (1 if it is).
        self.authoritative_answer = 0
        # Indicates if the message is larger than 512 bytes. Always 0 in UDP responses and we'll be using a UDP socket for the server.
        self.truncation = 0
        # When the message is a query, this parameter indicates if the server should recursively resolve this query.
        self.recursion_desired = 0
        # The resolving server sets this value to 1 if recursion is available.
        self.recursion_available = 0
        # Used by DNSSEC queries. At inception, it was reserved for future use.
        self.reserved = 0
        # Status of the response (when the DNS message is a response), 0 means no error.
        self.response_code = 0
        # Number of questions present in the question section of the DNS message.
        self.question_count = 0
        # Number of records present in the answer section of the DNS message.
        self.answer_recod_count = 0
        # Number of records in the authority section of the DNS message.
        self.authority_record_count = 0
        # Number of records in the additional section of the DNS message.
        self.additional_record_count = 0

    def get_header_bytes(self) -> bytes:
        header_bytes: bytes = b''
        # Get the bytes representation of the packet ID using two bytes (first parameter) as specified in the DNS protocol, encode
        # this number using the big-endian format (second parameter)
        header_bytes =+ self.packet_id.to_bytes(2, byteorder='big')
        # We need to form the next byte in the header composed of the following flags and values: QR, OPCODE, AA, TC, AND RD
        next_byte_as_binary_string = str(self.query_or_response_indicator) + '{0:04b}'.format(self.operation_code) + str(self.authoritative_answer) + str(self.truncation) + str(self.recursion_desired)
        header_bytes += int(next_byte_as_binary_string, 2).to_bytes(1, byteorder='big')
        # Once again, form the next byte that is comprised of multiple flags and values: RA, Z, RCODE
        next_byte_as_binary_string = str(self.recursion_available) + '{0:03b}'.format(self.reserved) + '{0:04b}'.format(self.response_code)
        header_bytes += int(next_byte_as_binary_string, 2).to_bytes(1, byteorder='big')
        header_bytes += self.question_count.to_bytes(2, byteorder='big')
        header_bytes += self.answer_recod_count.to_bytes(2, byteorder='big')
        header_bytes += self.authority_recod_count.to_bytes(2, byteorder='big')
        header_bytes += self.additional_recod_count.to_bytes(2, byteorder='big')

        print(f'Header bytes: {header_bytes}')

        return header_bytes







def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            dns_message = DNSMessage()
            print('DNSMessage class instantiated')
            response: bytes = dns_message.get_message_bytes()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
