import socket
import struct



fin_flag = 1
syn_flag = 1 << 1
rst_flag = 1 << 2
ack_flag = 1 << 4

def print_byte_string(byte_str):
    word = ""
    for byte in byte_str:
        word += "{:02x}".format(byte)
        if len(word) == 4:
            print(word)
            word = ""

def ip_addr_to_int(addr):
    return struct.unpack("!L", socket.inet_aton(addr))[0]

def ip_addr_to_checksum_value(addr):
    addr_int = ip_addr_to_int(addr)
    upper_bits = (addr_int & 0xFFFF0000) >> 16
    lower_bits= (addr_int & 0x0000FFFF)
    return upper_bits + lower_bits

def generate_tcp_header(
        src_addr, dst_addr, src_port, dst_port, seq_num, ack_num,
        data_offset_plus_reserved_bits, flags, window_size, data_len = 0):
    # Source Address
    checksum = ip_addr_to_checksum_value(src_addr)
    # Destination Address
    checksum += ip_addr_to_checksum_value(dst_addr)
    # Protocol
    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    checksum += 6
    # Length
    # TCP header length (in bytes) plus data length
    checksum += 20 + data_len
    # Source Port
    checksum += src_port
    # Source Port
    checksum += dst_port
    # Sequence Number
    checksum += (seq_num & 0xFFFF0000) >> 16
    checksum += (seq_num & 0x0000FFFF)
    # Acknowledge Number
    checksum += (ack_num & 0xFFFF0000) >> 16
    checksum += (ack_num & 0x0000FFFF)
    # Data offset + Reserved bits
    checksum += data_offset_plus_reserved_bits << 8
    # Flags
    checksum += flags
    # Window Size (max size)
    checksum += window_size

    upper_checksum_bits = (0xFFFF0000 & checksum) >> 16
    lower_checksum_bits = (0x0000FFFF & checksum)
    added_checksum_bits = upper_checksum_bits + lower_checksum_bits
    checksum = 0xFFFF - added_checksum_bits

    # Source Port
    tcp_header = struct.pack(">H", src_port)
    # Destination Port
    tcp_header += struct.pack(">H", dst_port)
    # Sequence Number
    tcp_header += struct.pack(">I", seq_num)
    # Acknowledge Number
    tcp_header += struct.pack(">I", ack_num)
    # Data offset + Reserved bits
    tcp_header += struct.pack(">B", data_offset_plus_reserved_bits)
    # Flags
    tcp_header += struct.pack(">B", flags)
    # Window Size (max size)
    tcp_header += struct.pack(">H", window_size)
    # Checksum
    tcp_header += struct.pack(">H", checksum)
    # Urgent pointer
    tcp_header += struct.pack(">H", 0)

    return tcp_header


def send_one(dst_addr, dst_port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)


    sock.bind(("0.0.0.0", 12345))

    sock.connect((dst_addr, dst_port))

    # From https://stackoverflow.com/a/41250854/5832619
    (src_addr, src_port) = sock.getsockname()


    # Syn packet
    payload = generate_tcp_header(
            src_addr, dst_addr, src_port, dst_port, 0, 0, 5 << 4,
            syn_flag, 65535)

    sock.send(payload)

    data = sock.recv(1024)
    print_byte_string(data)
    print("")

    data = sock.recv(1024)
    print_byte_string(data)
    print("")

    data = sock.recv(1024)
    print_byte_string(data)
    print("")

    """
    payload = generate_tcp_header(
            src_addr, dst_addr, src_port, dst_port, 0, 0, 5 << 4,
            syn_flag, 65535, len(payload))
    """

    sock.close()

    return


if __name__ == "__main__":
    print("Sending...")
    send_one("127.0.0.1", 4444, b"Hello TCP")

