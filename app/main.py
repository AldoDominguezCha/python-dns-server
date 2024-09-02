from __future__ import annotations
import socket

# Constants section TODO: Move to its own module
HEADER_LENGTH_IN_BYTES = 12
HEADER_PACKET_ID_LENGTH_IN_BYTES = 2
HEADER_QUESTION_COUNT_LENGTH_IN_BYTES = 2
HEADER_ANSWER_COUNT_LENGTH_IN_BYTES = 2
HEADER_AUTHORITY_COUNT_LENGTH_IN_BYTES = 2
HEADER_ADDITIONAL_COUNT_LENGTH_IN_BYTES = 2

# Manipulate a message, to set the data into it so we can send it as a byte sequence at the end
class DNSMessageEncoder(object):
    @staticmethod
    def __encode(number: int, number_of_bytes: int) -> bytes:
        # Get the sequence of bytes representing the number in big-endian format as required by the DNS specification
        return (number).to_bytes(number_of_bytes, byteorder='big')

    # Get the bytes representing the domain name (it will be encoded as a sequence of labels)
    @staticmethod
    def __encode_label_sequence(name: str) -> bytes:
        label_sequence = b''

        for segment in name.split('.'):
            label_sequence += DNSMessageEncoder.__encode(len(segment), 1) + segment.encode('UTF-8')
        label_sequence += b'\x00'

        return label_sequence
    
    @staticmethod
    def get_header_bytes(header: DNSMessageHeader) -> bytes:
        header_bytes: bytes = b''

        header_bytes += DNSMessageEncoder.__encode(header.packet_id, 2)

        # Encode this next byte composed by multiple header fields
        next_byte_as_binary_string = str(header.query_or_response_indicator) + '{0:04b}'.format(header.operation_code) + str(header.authoritative_answer) + str(header.truncation) + str(header.recursion_desired)
        header_bytes += DNSMessageEncoder.__encode(int(next_byte_as_binary_string, 2), 1)

        # Encode this next byte composed by multiple header fields
        next_byte_as_binary_string = str(header.recursion_available) + '{0:03b}'.format(header.reserved) + '{0:04b}'.format(header.response_code)
        header_bytes += DNSMessageEncoder.__encode(int(next_byte_as_binary_string, 2), 1)

        header_bytes += DNSMessageEncoder.__encode(header.question_count, 2)
        header_bytes += DNSMessageEncoder.__encode(header.answer_record_count, 2)
        header_bytes += DNSMessageEncoder.__encode(header.authority_record_count, 2)
        header_bytes += DNSMessageEncoder.__encode(header.additional_record_count, 2)

        print(f'Message header bytes encoded: {header_bytes}')

        # Sequence of bytes can be appended with one another, that's just what we did, grouping together the different header properties that conform a single byte
        # b'\x04' + b'\xd2' = b'\x04\xd2'
        return header_bytes
    
    @staticmethod
    def get_question_bytes(question: DNSQuestion) -> bytes:
        question_name = DNSMessageEncoder.__encode_label_sequence(question.domain_name)
        question_bytes: bytes = question_name + DNSMessageEncoder.__encode(question.record_type, 2) + DNSMessageEncoder.__encode(question.question_class, 2)
        
        return question_bytes
        
    @staticmethod
    def get_preamble_bytes(preamble: DNSRecordPreamble) -> bytes:
        preamble_bytes: bytes = DNSMessageEncoder.__encode_label_sequence(preamble.domain_name)
        preamble_bytes += DNSMessageEncoder.__encode(preamble.record_type, 2)
        preamble_bytes += DNSMessageEncoder.__encode(preamble.record_class, 2)
        preamble_bytes += DNSMessageEncoder.__encode(preamble.TTL, 4)
        preamble_bytes += DNSMessageEncoder.__encode(preamble.data_length, 2)

        return preamble_bytes

    @staticmethod
    def get_record_bytes(record: DNSRecord):
        encoded_ip = b''.join(DNSMessageEncoder.__encode(int(ip_byte), 1) for ip_byte in record.ip.split('.'))
        print(f'Encoded IP obtained in DNS record: {encoded_ip}')

        return DNSMessageEncoder.get_preamble_bytes(record.preamble) + encoded_ip
    
    
    @staticmethod
    def encode_message(dns_message: DNSMessage) -> bytes:
        message_bytes: bytes = DNSMessageEncoder.get_header_bytes(dns_message.header)
        message_bytes += b''.join([DNSMessageEncoder.get_question_bytes(question) for question in dns_message.questions])
        message_bytes += b''.join([DNSMessageEncoder.get_record_bytes(record) for record in dns_message.answers])

        return message_bytes

# Receive a raw DNS message (the sequence of bytes), extract the sections and the parts of each section,
# and parse the data to make it human-readable.
class DNSMessageParser(object):
    def __init__(self, raw_dns_message: bytes):
        self.__raw_message = raw_dns_message
        self.__message = DNSMessage()

        self.parse_header()
    
    @property
    def message(self):
        return self.__message


    def parse_header(self):
        header: bytes = self.__raw_message[0:HEADER_LENGTH_IN_BYTES]
        bytes_sequence_position = 0

        # Parse all the header fields/attributes
        packet_id = int.from_bytes(header[bytes_sequence_position:HEADER_PACKET_ID_LENGTH_IN_BYTES])
        bytes_sequence_position += HEADER_PACKET_ID_LENGTH_IN_BYTES

        # Take the next byte which is composed by multiple header fields
        next_composite_byte = header[bytes_sequence_position:bytes_sequence_position + 1]
        bytes_sequence_position += 1

        # From the byte to bits, removing the '0b' preffix
        next_composite_bits = format(int.from_bytes(next_composite_byte), '08b')
        query_response = int(next_composite_bits[0])
        operation_code = int(next_composite_bits[1:5], base=2)
        authoritative_answer = int(next_composite_bits[5])
        truncated_message = int(next_composite_bits[6])
        recursion_desired = int(next_composite_bits[7])

        self.message.header.packet_id = packet_id
        self.message.header.query_or_response_indicator = query_response
        self.message.header.operation_code = operation_code
        self.message.header.authoritative_answer = authoritative_answer
        self.message.header.truncation = truncated_message
        self.message.header.recursion_desired = recursion_desired

        # Take the next byte which is composed by multiple header fields
        next_composite_byte = header[bytes_sequence_position:bytes_sequence_position + 1]
        bytes_sequence_position += 1

        # From the byte to bits, removing the '0b' preffix
        next_composite_bits = format(int.from_bytes(next_composite_byte), '08b')
        recursion_available = int(next_composite_bits[0])
        reserved = int(next_composite_bits[1:4], base=2)
        response_code = int(next_composite_bits[4:8], base=2)

        self.message.header.recursion_available = recursion_available
        self.message.header.reserved = reserved
        self.message.header.response_code = response_code

        self.message.header.question_count = int.from_bytes(header[bytes_sequence_position : bytes_sequence_position + HEADER_QUESTION_COUNT_LENGTH_IN_BYTES])
        bytes_sequence_position += HEADER_QUESTION_COUNT_LENGTH_IN_BYTES


        self.message.header.answer_record_count = int.from_bytes(header[bytes_sequence_position : bytes_sequence_position + HEADER_ANSWER_COUNT_LENGTH_IN_BYTES])
        bytes_sequence_position += HEADER_ANSWER_COUNT_LENGTH_IN_BYTES

        self.message.header.authority_record_count = int.from_bytes(header[bytes_sequence_position : bytes_sequence_position + HEADER_AUTHORITY_COUNT_LENGTH_IN_BYTES])
        bytes_sequence_position += HEADER_AUTHORITY_COUNT_LENGTH_IN_BYTES

        self.message.header.additional_record_count = int.from_bytes(header[bytes_sequence_position : bytes_sequence_position + HEADER_ADDITIONAL_COUNT_LENGTH_IN_BYTES])

        # TODO: Remove
        # print(f'In parser, parsed question count: {self.message.header.question_count}')
        # print(f'In parser, parsed answer record count: {self.message.header.answer_record_count}')
        # print(f'In parser, parsed authority record count: {self.message.header.authority_record_count}')
        # print(f'In parser, parsed authority record count: {self.message.header.additional_record_count}')


class DNSMessage:
    def __init__(self, packet_id: int = 0, query_response: int = 0):
        self.__header: DNSMessageHeader = DNSMessageHeader(packet_id, query_response)
        self.__questions = []
        self.__answers = []

    @property
    def header(self):
        return self.__header

    @property
    def questions(self):
        return self.__questions

    @property
    def answers(self):
        return self.__answers
    
    def add_message_question(self, dns_question):
        self.questions.append(dns_question)
        self.__header.question_count += 1

    def add_message_answer(self, dns_record):
        self.answers.append(dns_record)
        self.__header.answer_record_count += 1
        

class DNSMessageHeader:
    def __init__(self, packet_id: int = 0, query_response: int = 0):
        self.packet_id = packet_id
        self.query_or_response_indicator = query_response
        self.operation_code = 0
        self.authoritative_answer = 0
        self.truncation = 0
        self.recursion_desired = 0
        self.recursion_available = 0
        self.reserved = 0
        self.response_code = 0
        self.question_count = 0
        self.answer_record_count = 0
        self.authority_record_count = 0
        self.additional_record_count = 0
        
class DNSQuestion:
    def __init__(self, domain_name, record_type, question_class):
        self.domain_name: str = domain_name
        self.record_type: int = record_type
        self.question_class: int = question_class
        

class DNSRecord:
    def __init__(self, preamble: DNSRecordPreamble, ip_address: str):
        self.preamble = preamble
        self.ip = ip_address
        

class DNSRecordPreamble:
    def __init__(self, domain_name, record_type, record_class, time_to_live, data_length):
        self.domain_name: str = domain_name
        self.record_type: int = record_type
        self.record_class = record_class
        self.TTL = time_to_live
        self.data_length = data_length

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    # TODO: Replace this with a ThreadPoolExecutor
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            # Build DNS response message
            # TODO: Create a writer class for this
            parser = DNSMessageParser(buf)
            message = parser.message

            print(f'ID obtained: {message.header.packet_id}')

            # Set up the response message properties
            message.header.query_or_response_indicator = 1
            message.header.authoritative_answer = 0
            message.header.truncation = 0
            message.header.recursion_available = 0
            message.header.reserved = 0
            message.header.response_code = 0 if not message.header.operation_code else 4
            message.add_message_question(DNSQuestion('codecrafters.io', 1, 1))
            message.add_message_answer(DNSRecord(DNSRecordPreamble('codecrafters.io', 1, 1, 60, 4), '8.8.8.8'))


            response: bytes = DNSMessageEncoder.encode_message(message)
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
