import socket
import struct
import textwrap

# Function to unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to format MAC address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Function to unpack IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Function to format an IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Function to format the data into a readable multiline string
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{0:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Main function to capture and analyze network traffic
def main():
    # Create a raw socket to capture network packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        # Receive raw data from the network
        raw_data, addr = conn.recvfrom(65536)
        
        # Unpack the Ethernet frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
        
        # If the Ethernet protocol is IPv4, process the packet further
        if eth_proto == 8:
            ttl, proto, src, target, data = ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'TTL: {ttl}, Protocol: {proto}, Source: {src}, Target: {target}')
            
            # Display the payload data in a readable format
            print('Data: {}'.format(format_multi_line("\t", data)))

# Entry point for the script
if __name__ == "__main__":
    main()
