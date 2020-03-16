# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from socket import *
import struct

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
        print(f"Received a packet from {packet_source}")
        # if it is the wrong server then don't parse
        # send error to the new server and wait for ack from the old server
        in_packet = self._parse_udp_packet(packet_data)
        if in_packet == -1:
            del self.packet_buffer[0::]
            return
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        if out_packet != -1:
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

        packet_type = struct.unpack("! H", packet_bytes[0:2])
        in_packet.append(packet_type)

        if TftpProcessor.TftpPacketType.ACK == packet_type :
            block_number = struct.unpack("! H",packet_bytes[2:4])
            in_packet.append(block_number)
            #check the block no saved if equal or error

        elif TftpProcessor.TftpPacketType.DATA == packet_type :
            block_number = struct.unpack("! H", packet_bytes[2:4])
            length_data = len(packet_bytes[4:])
            data_of_current_packet = struct.unpack("!%ds", length_data,packet_bytes[4:])
            in_packet.append(block_number,data_of_current_packet)

        elif TftpProcessor.TftpPacketType.ERROR == packet_type:
            error_code = struct.unpack("! H",packet_bytes[2:4])
            length_err = len(packet_bytes[4:])
            error_message = struct.unpack("!%ds", length_err,packet_bytes[4:length_err-1])
            in_packet.append(error_code,error_message)
        else:
            self.print_error(4)
            return -1


        return in_packet

    #Only send error packet if the source TID is not the expected
    def create_error_packet(self):

        err_msg_id = "Unknown transfer ID."
        error_packet = struct.pack("!HH %ds b", 5, 5, len(err_msg_id), err_msg_id, 0)
        return error_packet

    #print the error received from server then terminate
    def print_error(self,error_code):
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


    def read_file(self,file_path_on_server):
        # Reading a file
        # if multiple of 512 then add an empty packet
        # return packet to be put in buffer
        file_len = os.stat(file_path_on_server).st_size
        with open(file_path_on_server, 'rb') as f:
            if last_block_no > ceil(file_len/512):
                # empty packet -- terminate
                #return b''
                return -1

            else :
                f.seek(self.last_block_no * 512)
                read_data = f.read(512)
                data_string = read_data.decode('utf-8')
            # if read_data<512 -> last packet then wait last ack then terminate
            #check end of file, send empty packet if multiple of 512
            # if not read_data:
                return struct.pack("!H H %ds b", 2, self.last_block_no, len(data_string), data_string, 0)

    def write_file(self,file_path_on_server, data):
        if data :
            f = open(file_path_on_server, 'wb')
            f.write(data)
        else :
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
        # blocknumber = 0 send first packet
        if TftpProcessor.TftpPacketType.ACK == packet_type :
                #upload
            #if input_packet[1] == 0 :
                # file_all  = struct.unpack("%ds",input_packet[2::])
                # file_name = file_all[2:(index(0))]
            block_check = self.check_upload_block_number(input_packet[1])
            if self.flag_sent > 2:
                return -1
            if block_check ==1:
                return self.read_file(self.file_name)
            elif block_check ==0:
                return self.read_file(self.file_name)
            else:
                self.print_error(0)
                return -1

        elif TftpProcessor.TftpPacketType.DATA == packet_type :
            #download
            block_check = self.check_download_block_number(input_packet[1])
            if block_check == 1:
                chk  = self.write_file(self.file_name, input_packet[2])
                #here check length of returned if ==0 because non terminate or signal end of file
            elif block_check == 0:
                chk = self.write_file(self.file_name, input_packet[2])
            else:
                #need to terminate here
                self.print_error(0)
                return -1
            # if blockcheck = 1/0 not -1
            if self.flag_sent <= 2:
                write_file("C:\\Desktop\out",input_packet[2])
            #write into file and send ack
            # check packet empty or not
            if chk ==-1 or self.flag_sent > 2:
                return -1
            else:
                out_packet = struct.pack("!HH",2,input_packet[1])
                return out_packet

        elif TftpProcessor.TftpPacketType.ERROR == packet_type:
            print_error(input_packet[1])
            return -1
            #terminate except for resend

    def check_download_block_number(self,block_no):
        if block_no == self.last_block_no + 1 :
            self.last_block_no +=1
            return 1
            #write/download next
        elif block_no == self.last_block_no  :
            self.flag_sent +=1
            #need to resend  last packet ack
            return 0
        elif block_no > self.last_block_no+1 :
            #error wrong block number
            return -1

    def check_upload_block_number(self,block_no):
        if block_no == self.last_block_no:
            self.last_block_no +=1
            return 1
            #upload next
        elif block_no < self.last_block_no :
            #need to resend  last packet data
            self.flag_sent +=1
            self.last_block_no = block_no + 1
            return 0
        elif block_no > self.last_block_no :
            #error wrong block number
            return -1

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):

        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        #return packet to be put in buffer
        return struct.pack("!H %ds b %ds b",1,len(file_path_on_server),file_path_on_server,0, len("octet"),"octet",0)

    def upload_file(self, file_path_on_server):

        return struct.pack("!H %ds b %ds b",2,len(file_path_on_server),file_path_on_server,0, len("octet"),"octet",0)


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

def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass

def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
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

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "C:\\Users\H.Nazmy\Desktop\\text.txt")

    # Modify this as needed.

    # first setup socket
    client_socket, server_address =  setup_sockets(ip_address)

    #call process udp
    tftp_processor = TftpProcessor()
    tftp_processor.file_name = file_name
    # get request
    if operation == "push":
        request = tftp_processor.upload_file(file_name)
    else :
        request = tftp_processor.request_file(file_name)
    #and add it to buffer to get file_name
    #tftp_processor.packet_buffer.append(request)

    # send request
    client_socket.sendto(request, server_address)

    client_socket.settimeout(20)
    # recv
    try:
        server_packet, address = client_socket.recvfrom(516)
    except socket.timeout:
        print("Request TIMEOUT")
        client_socket.close()
    #check the server address
    # after receive
    tftp_processor.process_udp_packet(server_packet, address)

    #if operation is push and response is error
    #if operation == "push":

    # run
    while True :

            if tftp_processor.has_pending_packets_to_be_sent():
                client_socket.sendto(tftp_processor.get_next_output_packet(), address)
                client_socket.settimeout(20)
                try:
                    reply, temp_address = client_socket.recvfrom(516)
                    if check_server_address(temp_address, address):
                        tftp_processor.process_udp_packet(reply, address)
                    else:
                        client_socket.sendto(tftp_processor.create_error_packet(), temp_address)
                except socket.timeout:
                        print("TIMEOUT")
                        break
            else :
                print("Connection closed")
                break
    client_socket.close()

if __name__ == "__main__":
    main()
