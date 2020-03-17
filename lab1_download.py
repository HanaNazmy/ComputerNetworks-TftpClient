# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import math


class TftpProcessor(object):
    """
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.


    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.last_block_no = 0
        self.flag_sent = 0
        self.file_name = ""
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print("**********\tEntered Processor\t**********")
        print(f"Received a packet from {packet_source}")
        # print("Packet data is ...")
        # print(packet_data)
        in_packet = self._parse_udp_packet(packet_data)
        # print("In_packet is -->")
        # print(in_packet)
        if in_packet == -1:
            del self.packet_buffer[0::]
            return
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        if out_packet != -1:
            print("****************")
            print("OUT_PACKET IS ", out_packet)
            # print("Size is ", len(out_packet))
            self.packet_buffer.append(out_packet)
        else:
            del self.packet_buffer[0::]
        return

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        in_packet = []
        # Unpack returns a tuple not integer
        packet_type = struct.unpack("! H", packet_bytes[0:2])
        packet_type = packet_type[0]
        print("Packet type is --> ", packet_type)
        in_packet.append(packet_type)

        if TftpProcessor.TftpPacketType.ACK.value == packet_type:
            block_number = struct.unpack("! H", packet_bytes[2:4])
            block_number = block_number[0]
            print("Block number is --> ", block_number)
            in_packet.append(block_number)

        elif TftpProcessor.TftpPacketType.DATA.value == packet_type:
            block_number = struct.unpack("! H", packet_bytes[2:4])
            block_number = block_number[0]
            length_data = len(packet_bytes[4:])
            data_of_current_packet = struct.unpack("!%ds" % length_data, packet_bytes[4:])
            # print("Data of current ...")
            # print(data_of_current_packet)
            data_of_current_packet = data_of_current_packet[0]
            in_packet.append(block_number)
            print("Block_number --> ", block_number)
            in_packet.append(data_of_current_packet)

        elif TftpProcessor.TftpPacketType.ERROR.value == packet_type:
            error_code = struct.unpack("! H", packet_bytes[2:4])
            error_code = error_code[0]
            # print("Error code")
            # print(error_code)
            print("Packet bytes are --> ", packet_bytes)
            length_err = len(packet_bytes[4:])
            # print("Length of err is")
            # print(length_err)
            # print("Packet bytes are")
            # print(packet_bytes)
            error_message = struct.unpack('!%ds' % length_err, packet_bytes[4:])
            error_message = error_message[0]
            print("After --> ", error_message)
            # print(type(error_message))
            error_message = error_message.decode(encoding='utf-8')
            error_message = error_message[0:len(error_message)-2]
            # print(len(error_message))
            # print(type(error_message))
            in_packet.append(error_code)
            in_packet.append(error_message)
        else:
            self.print_error(4)
            return -1

        return in_packet

    # Only send error packet if the source TID is not the expected
    def create_error_packet(self):

        err_msg_id = bytes("Unknown transfer ID.", encoding='utf-8')
        error_packet = struct.pack('!HH %ds b' % len(err_msg_id), 5, 5, err_msg_id, 0)
        return error_packet

    # print the error received from server then terminate
    def print_error(self, error_code):
        if error_code == 0:
            print("Block number violation")
        elif error_code == 1:
            print("File not found.")
        elif error_code == 2:
            print("Access violation.")
        elif error_code == 3:
            print("Disk full or allocation exceeded.")
        elif error_code == 4:
            print("Illegal TFTP operation.")
        elif error_code == 5:
            print("Unknown transfer ID.")
        elif error_code == 6:
            print("File already exists.")
        elif error_code == 7:
            print("No such user.")
        else:
            print("Unknown error")

    def read_file(self, file_path_on_server):
        # Reading a file
        # if multiple of 512 then add an empty packet
        # return packet to be put in buffer
        file_len = os.stat(file_path_on_server).st_size
        with open(file_path_on_server, 'rb') as f:
            if self.last_block_no > math.ceil(file_len/512):
                return -1
            else:
                f.seek(self.last_block_no * 512)
                read_data = f.read(512)
                data_string = read_data.decode('utf-8')
            # if read_data<512 -> last packet then wait last ack then terminate
            # check end of file, send empty packet if multiple of 512
            # if not read_data:
                data_string_bytes = bytes(data_string, encoding='utf-8')
                return struct.pack('!H H %ds b' % (len(data_string_bytes)), 2, self.last_block_no, data_string_bytes, 0)

    def write_file(self, file_path_on_server, data):
        f = open(file_path_on_server, 'ab')
        if data:
            f.write(data)
        else:
            # terminate
            f.close()
            return -1

    # fill our buffer (either full of ack or data_packet)
    # data parse do some logic concatenate any packet data and when reach end write ficle (all in do some logic)
    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        ##
        packet_type = input_packet[0]
        # print("Here packet type -->", packet_type)
        if TftpProcessor.TftpPacketType.ACK.value == packet_type:
            # upload
            block_check = self.check_upload_block_number(input_packet[1])
            print("Block check is ", block_check)
            if block_check == -1:
                self.print_error(0)
                return -1
            else:
                if self.flag_sent <= 2 and (block_check == 1 or block_check == 0):
                    check = self.read_file(self.file_name)
                    if check != -1:
                        out_packet = struct.pack("!HH", 3, self.last_block_no)
                        # print("Inside outpack is ", out_packet)
                        return out_packet
                else:
                    return -1
            # block_check = self.check_upload_block_number(input_packet[1])
            # if self.flag_sent > 2:
            #     return -1
            # if block_check == 1:
            #     return self.read_file(self.file_name)
            # elif block_check == 0:
            #     return self.read_file(self.file_name)
            # else:
            #     self.print_error(0)
            #     return -1

        elif TftpProcessor.TftpPacketType.DATA.value == packet_type:
            # download
            block_check = self.check_download_block_number(input_packet[1])
            print("Block check is ", block_check)
            if block_check == -1:
                self.print_error(0)
                return -1
            else:
                if self.flag_sent <= 2 and (block_check == 1 or block_check == 0):
                    check = self.write_file(self.file_name, input_packet[2])
                    if check != -1:
                        out_packet = struct.pack("!HH", 4, input_packet[1])
                        # print("Inside outpack is ", out_packet)
                        return out_packet
                else:
                    return -1


        elif TftpProcessor.TftpPacketType.ERROR.value == packet_type:
            self.print_error(input_packet[1])
            return -1
            # terminate except for resend

    def check_download_block_number(self, block_no):
        if block_no == self.last_block_no + 1:
            self.last_block_no += 1
            return 1
            # write/download next
        elif block_no == self.last_block_no:
            self.flag_sent += 1
            # need to resend  last packet ack
            return 0
        elif block_no > self.last_block_no+1:
            # error wrong block number
            return -1

    def check_upload_block_number(self, block_no):
        if block_no == self.last_block_no:
            self.last_block_no += 1
            return 1
            # upload next
        elif block_no < self.last_block_no:
            # need to resend  last packet data
            self.flag_sent += 1
            self.last_block_no = block_no + 1
            return 0
        elif block_no > self.last_block_no:
            # error wrong block number
            return -1

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):

        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        # return packet to be put in buffer
        s1 = bytes(file_path_on_server, encoding='utf-8')
        s2 = "octet".encode('utf-8')
        return struct.pack('!H %ds B %ds B' % (len(s1), len(s2)), 1, s1, 0, s2, 0)


    def upload_file(self, file_path_on_server):
        s1 = bytes(file_path_on_server, encoding='utf-8')
        s2 = "octet".encode('utf-8')
        return struct.pack('!H %ds b %ds b' % (len(s1), len(s2)), 2, s1, 0, s2, 0)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return client_socket, server_address


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_server_address(temp_address, old_address):
    if temp_address == old_address:
        return True
    else:
        return False


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    # print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    # check_file_name()
    # print("*" * 50)
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "C:\\Users\\H.Nazmy\\Desktop\\text.txt")
    # first setup socket
    client_socket, server_address = setup_sockets(ip_address)
    # call process udp
    tftp_processor = TftpProcessor()
    tftp_processor.file_name = file_name
    print("file name is ")
    print(tftp_processor.file_name)
    # get request
    if operation == "push":
        request = tftp_processor.upload_file(file_name)
        print(f"Attempting to upload [{file_name}]...")
    elif operation == "pull":
        request = tftp_processor.request_file(file_name)
        print(f"Attempting to download [{file_name}]...")
    # and add it to buffer to get file_name
    # tftp_processor.packet_buffer.append(request)

    print("Request is")
    print(request)
    # send request
    client_socket.sendto(request, server_address)

    client_socket.settimeout(5)
    # recv
    try:
        server_packet, address = client_socket.recvfrom(516)
        # print('Server packet is ...')
        # print(server_packet)
        # print('New ip address is ...')
        # print(address)
        tftp_processor.process_udp_packet(server_packet, address)
    except socket.timeout:
        # exit program
        print("Request TIMEOUT")
        client_socket.close()

    # if operation is push and response is error
    # if operation == "push":

    # run
    while True:

        if tftp_processor.has_pending_packets_to_be_sent():
            client_socket.sendto(tftp_processor.get_next_output_packet(), address)
            client_socket.settimeout(5)
            try:
                reply, temp_address = client_socket.recvfrom(516)
                if check_server_address(temp_address, address):
                    tftp_processor.process_udp_packet(reply, address)
                    print("*******************************************")
                else:
                    client_socket.sendto(tftp_processor.create_error_packet(), temp_address)
            except socket.timeout:
                print("TIMEOUT")
                break
        else:
            print("Connection closed")
            break
    client_socket.close()


if __name__ == "__main__":
    main()
