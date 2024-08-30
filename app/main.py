from __future__ import annotations
import socket

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
        # self.message = DNSMessage()

    def parse_message_id(self):
        header_bytes = self.__raw_message[0:16]

        # TODO: This is now working, let us parse the entire header of the message and add it to a resulting
        # message object
        # TODO: Define the byte ranges as constants
        packet_id = int.from_bytes(header_bytes[0:2])
        print(f'Found ID in parsed message: {packet_id}')

        return packet_id



class DNSMessage:
    def __init__(self, packet_id: int = 0, query_response: int = 0):
        self.__header: DNSMessageHeader = DNSMessageHeader(packet_id, query_response)
        # TODO: Make them private with a getter
        self.questions = []
        self.answers = []

    @property
    def header(self):
        return self.__header
    
    def add_message_question(self, dns_question):
        self.questions.append(dns_question)
        self.__header.increment_question_count()

    def add_message_answer(self, dns_record):
        self.answers.append(dns_record)
        self.__header.increment_answer_count()
        

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
        self.__question_count = 0
        self.__answer_record_count = 0
        self.__authority_record_count = 0
        self.__additional_record_count = 0

    @property
    def question_count(self):
        return self.__question_count

    @property
    def answer_record_count(self):
        return self.__answer_record_count

    @property
    def authority_record_count(self):
        return self.__authority_record_count

    @property
    def additional_record_count(self):
        return self.__additional_record_count
    
    def increment_question_count(self):
        self.__question_count += 1

    def increment_answer_count(self):
        self.__answer_record_count += 1
        
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
            packet_id = parser.parse_message_id()

            dns_response_message = DNSMessage(packet_id, 1)
            dns_response_message.add_message_question(DNSQuestion('codecrafters.io', 1, 1))
            dns_response_message.add_message_answer(DNSRecord(DNSRecordPreamble('codecrafters.io', 1, 1, 60, 4), '8.8.8.8'))


            response: bytes = DNSMessageEncoder.encode_message(dns_response_message)
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
