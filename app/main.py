import socket

'''
Using this decorator we are extending the parameter class, we are generating a new subclass with an additional method
to get the label sequence as bytes. This is unnecessary in reality, as simple inheritance would have sufficed using 
LabelSequenceParser as the base class, but it's an interesting example about applying decorators to a class instead of
a function.
'''
def label_sequence(cls):
    class LabelSequenceParser(cls):
        def __init__(self, *args, **kargs):
            super().__init__(*args, **kargs)

        def get_label_sequence_bytes(domain_name: str):
            label_sequence = b''

            name_segments = domain_name.split('.')
            for segment in name_segments:
                label_sequence += len(segment).to_bytes(1, byteorder='big') + segment.encode('UTF-8')
            label_sequence += b'\x00'

            return label_sequence

    return LabelSequenceParser


class DNSMessage:
    def __init__(self):
        self.header: DNSMessageHeader = DNSMessageHeader()
        # It's a list of questions
        self.questions = []
        # It's a list of answer records to the questions
        self.answers = []
    
    def add_message_question(self, dns_question):
        self.questions.append(dns_question)
        self.header.increment_question_count()

    def add_message_answer(self, dns_record):
        self.answers.append(dns_record)
        self.header.increment_answer_count()
    
    def get_message_bytes(self) -> bytes:
        message_bytes = b''
        message_bytes += self.header.get_header_bytes()
        message_bytes += ''.join([question.question_bytes for question in self.questions])
        message_bytes += ''.join([record.get_record_bytes() for record in self.answers])

        return message_bytes

class DNSMessageHeader:
    """Abstraction of the DNS message header"""

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
        self.answer_record_count = 0
        # Number of records in the authority section of the DNS message.
        self.authority_record_count = 0
        # Number of records in the additional section of the DNS message.
        self.additional_record_count = 0
    
    def increment_question_count(self):
        self.question_count += 1

    def increment_answer_count(self):
        self.answer_record_count += 1

    def get_header_bytes(self) -> bytes:
        header_bytes: bytes = b''
        # Get the bytes representation of the packet ID using two bytes (first parameter) as specified in the DNS protocol, encode
        # this number using the big-endian format (second parameter)
        header_bytes += self.packet_id.to_bytes(2, byteorder='big')
        # We need to form the next byte in the header composed of the following flags and values: QR, OPCODE, AA, TC, AND RD
        next_byte_as_binary_string = str(self.query_or_response_indicator) + '{0:04b}'.format(self.operation_code) + str(self.authoritative_answer) + str(self.truncation) + str(self.recursion_desired)
        header_bytes += int(next_byte_as_binary_string, 2).to_bytes(1, byteorder='big')
        # Once again, form the next byte that is comprised of multiple flags and values: RA, Z, RCODE
        next_byte_as_binary_string = str(self.recursion_available) + '{0:03b}'.format(self.reserved) + '{0:04b}'.format(self.response_code)
        header_bytes += int(next_byte_as_binary_string, 2).to_bytes(1, byteorder='big')
        header_bytes += self.question_count.to_bytes(2, byteorder='big')
        header_bytes += self.answer_record_count.to_bytes(2, byteorder='big')
        header_bytes += self.authority_record_count.to_bytes(2, byteorder='big')
        header_bytes += self.additional_record_count.to_bytes(2, byteorder='big')

        print(f'Message header bytes encoded: {header_bytes}')

        # Sequence of bytes can be appended with one another, that's just what we did, grouping together the different header properties that conform a single byte
        # b'\x04' + b'\xd2' = b'\x04\xd2'
        return header_bytes

@label_sequence
class DNSQuestion:
    def __init__(self, domain_name, record_type, question_class):
        self.__domain_name: str = domain_name
        self.__record_type: int = record_type
        self.__question_class: int = question_class

    def set_domain_name(self, readable_domain_name: str):
        self.__domain_name = readable_domain_name
    def set_type(self, record_type: int):
        self.__record_type = record_type
    def set_question_class(self, question_class: int):
        self.__question_class = question_class
    
    @property
    def question_bytes(self) -> bytes:
        question = b''
        question_name = self.get_label_sequence_bytes(self.__domain_name)
        question += question_name + self.__record_type.to_bytes(2, byteorder='big') + self.__question_class.to_bytes(2, byteorder='big')
        
        return question

class DNSRecord:
    def __init__(self, preamble, ip_address: str):
        self.preamble = preamble
        self.ip = ip_address
    
    def get_record_bytes(self):
        encoded_ip = ''.join(int(ip_byte).to_bytes(1, byteorder='big') for ip_byte in self.ip.slice('.'))
        print(f'Encoded IP obtained in DNS record: {encoded_ip}')

        return self.preamble.preamble_bytes + encoded_ip


@label_sequence
class DNSRecordPreamble:
    def __init__(self, domain_name, record_type, record_class, time_to_live, data_length):
        self.__domain_name: str = domain_name
        self.__record_type: int = record_type
        self.__record_class = record_class
        self.__TTL = time_to_live
        self.__data_length = data_length

    @property
    def preamble_bytes(self):
        preamble_bytes: bytes = self.get_label_sequence_bytes(self.__domain_name)
        preamble_bytes += self.__record_type.to_bytes(2, byteorder='big')
        preamble_bytes += self.__record_class.to_bytes(2, byteorder='big')
        preamble_bytes += self.__TTL.to_bytes(4, byteorder='big')
        preamble_bytes += self.__data_length.to_bytes(2, byteorder='big')



def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            # Build DNS response message
            dns_message = DNSMessage()
            dns_message.add_message_question(DNSQuestion('codecrafters.io', 1, 1))
            dns_message.add_message_answer(DNSRecord(DNSRecordPreamble('codecrafters.io', 1, 1, 60, 4), '8.8.8.8'))


            response: bytes = dns_message.get_message_bytes()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
