#!/usr/bin/env python3

import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime

# Protocol numbers
PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class PacketSniffer:
    """Main packet sniffer class"""
    
    def __init__(self, interface=None, count=10, output_file=None):
        
        self.interface = interface
        self.count = count
        self.output_file = output_file
        self.packet_count = 0
        self.captured_data = []
        
    def create_socket(self):
        try:
            # Create raw socket - requires root/admin privileges
            # For Linux/Mac: socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)
            # For Windows: socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            
            if sys.platform.startswith('win'):
                # Windows configuration
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Mac configuration
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                
            return sock
        except PermissionError:
            print(f"{Colors.FAIL}[ERROR] Root/Administrator privileges required!{Colors.END}")
            print(f"{Colors.WARNING}Run with: sudo python3 {sys.argv[0]}{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR] Failed to create socket: {e}{Colors.END}")
            sys.exit(1)
    
    def start_sniffing(self):
        """Start capturing packets"""
        # Elite ASCII Art Banner
        print(f"{Colors.FAIL}")
        print("        ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗")
        print("        ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝")
        print("        ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ ")
        print("        ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ ")
        print("        ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗")
        print("        ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝")
        print()
        print("        ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ ")
        print("        ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗")
        print("        ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝")
        print("        ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗")
        print("        ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║")
        print("        ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝")
        print(f"{Colors.END}")
        print(f"{Colors.CYAN}        ╔═══════════════════════════════════════════════════════════╗")
        print(f"        ║      PACKET INTERCEPTOR  |  DEEP PACKET ANALYSIS v1.0     ║")
        print(f"        ║                    [ N1xR00t~# Security ]                 ║")
        print(f"        ╚═══════════════════════════════════════════════════════════╝{Colors.END}")
        print(f"{Colors.WARNING}        ⚠️  WARNING: AUTHORIZED PERSONNEL ONLY  ⚠️{Colors.END}")
        print()
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("=" * 80)
        print("NETWORK PACKET SNIFFER - Started")
        print("=" * 80)
        print(f"{Colors.END}")
        print(f"{Colors.CYAN}[INFO] Initializing packet capture...{Colors.END}")
        
        if self.count == 0:
            print(f"{Colors.WARNING}[INFO] Capturing packets indefinitely (Ctrl+C to stop){Colors.END}")
        else:
            print(f"{Colors.GREEN}[INFO] Will capture {self.count} packets{Colors.END}")
        
        print(f"\n{Colors.BOLD}Starting capture...{Colors.END}\n")
        
        sock = self.create_socket()
        
        try:
            while self.count == 0 or self.packet_count < self.count:
                raw_data, addr = sock.recvfrom(65535)
                self.packet_count += 1
                
                print(f"{Colors.BOLD}{'=' * 80}{Colors.END}")
                print(f"{Colors.HEADER}PACKET #{self.packet_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
                print(f"{Colors.BOLD}{'=' * 80}{Colors.END}\n")
                
                # Parse Ethernet frame
                if sys.platform.startswith('win'):
                    # On Windows, we get IP packets directly
                    ip_header = self.parse_ipv4_packet(raw_data)
                else:
                    # On Linux/Mac, parse Ethernet frame first
                    eth_header = self.parse_ethernet_frame(raw_data)
                    print(eth_header)
                    
                    # Parse IP packet if it's IPv4
                    if len(raw_data) > 14:
                        ip_header = self.parse_ipv4_packet(raw_data[14:])
                
                print(ip_header)
                print()
                
                # Store packet info
                packet_info = {
                    'number': self.packet_count,
                    'timestamp': datetime.now().isoformat(),
                    'data': raw_data.hex()
                }
                self.captured_data.append(packet_info)
                
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[INFO] Packet capture interrupted by user{Colors.END}")
        finally:
            if sys.platform.startswith('win'):
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            self.print_summary()
            
            if self.output_file:
                self.save_to_file()
    
    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame header"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        
        return (f"{Colors.CYAN}[Ethernet Frame]{Colors.END}\n"
                f"  Destination MAC: {self.format_mac(dest_mac)}\n"
                f"  Source MAC:      {self.format_mac(src_mac)}\n"
                f"  Protocol:        {hex(proto)}")
    
    def parse_ipv4_packet(self, data):
        """Parse IPv4 packet header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        protocol_name = PROTOCOLS.get(proto, f'Unknown({proto})')
        
        result = (f"{Colors.GREEN}[IPv4 Packet]{Colors.END}\n"
                 f"  Version:         {version}\n"
                 f"  Header Length:   {header_length} bytes\n"
                 f"  TTL:             {ttl}\n"
                 f"  Protocol:        {protocol_name}\n"
                 f"  Source IP:       {self.format_ipv4(src)}\n"
                 f"  Destination IP:  {self.format_ipv4(target)}")
        
        # Parse transport layer protocols
        if proto == 6:  # TCP
            result += "\n" + self.parse_tcp_segment(data[header_length:])
        elif proto == 17:  # UDP
            result += "\n" + self.parse_udp_segment(data[header_length:])
        elif proto == 1:  # ICMP
            result += "\n" + self.parse_icmp_packet(data[header_length:])
        
        return result
    
    def parse_tcp_segment(self, data):
        """Parse TCP segment"""
        if len(data) < 20:
            return ""
        
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        flags = []
        if flag_syn: flags.append('SYN')
        if flag_ack: flags.append('ACK')
        if flag_fin: flags.append('FIN')
        if flag_rst: flags.append('RST')
        if flag_psh: flags.append('PSH')
        if flag_urg: flags.append('URG')
        
        result = (f"{Colors.BLUE}[TCP Segment]{Colors.END}\n"
                 f"  Source Port:     {src_port}\n"
                 f"  Dest Port:       {dest_port}\n"
                 f"  Sequence:        {sequence}\n"
                 f"  Acknowledgment:  {acknowledgment}\n"
                 f"  Flags:           {', '.join(flags) if flags else 'None'}")
        
        # Display payload if available
        if len(data) > offset:
            payload = data[offset:]
            result += f"\n{Colors.WARNING}[Payload Preview]{Colors.END}\n"
            result += self.format_payload(payload)
        
        return result
    
    def parse_udp_segment(self, data):
        """Parse UDP segment"""
        if len(data) < 8:
            return ""
        
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        
        result = (f"{Colors.BLUE}[UDP Segment]{Colors.END}\n"
                 f"  Source Port:     {src_port}\n"
                 f"  Dest Port:       {dest_port}\n"
                 f"  Length:          {length}")
        
        # Display payload if available
        if len(data) > 8:
            payload = data[8:]
            result += f"\n{Colors.WARNING}[Payload Preview]{Colors.END}\n"
            result += self.format_payload(payload)
        
        return result
    
    def parse_icmp_packet(self, data):
        """Parse ICMP packet"""
        if len(data) < 4:
            return ""
        
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        
        return (f"{Colors.BLUE}[ICMP Packet]{Colors.END}\n"
               f"  Type:            {icmp_type}\n"
               f"  Code:            {code}\n"
               f"  Checksum:        {checksum}")
    
    def format_mac(self, bytes_addr):
        """Format MAC address"""
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    
    def format_ipv4(self, addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))
    
    def format_payload(self, data, max_bytes=50):
        """Format payload data for display"""
        # Show first max_bytes in hex and ASCII
        preview = data[:max_bytes]
        
        hex_str = ' '.join(f'{b:02x}' for b in preview)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in preview)
        
        result = f"  Hex:  {hex_str}\n"
        result += f"  ASCII: {ascii_str}\n"
        
        if len(data) > max_bytes:
            result += f"  ... ({len(data) - max_bytes} more bytes)\n"
        
        return result
    
    def print_summary(self):
        """Print capture summary"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("=" * 80)
        print("CAPTURE SUMMARY")
        print("=" * 80)
        print(f"{Colors.END}")
        print(f"{Colors.GREEN}Total packets captured: {self.packet_count}{Colors.END}\n")
    
    def save_to_file(self):
        """Save captured packets to file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"Network Packet Capture\n")
                f.write(f"Captured on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total packets: {self.packet_count}\n")
                f.write("=" * 80 + "\n\n")
                
                for packet in self.captured_data:
                    f.write(f"Packet #{packet['number']}\n")
                    f.write(f"Timestamp: {packet['timestamp']}\n")
                    f.write(f"Raw Data (hex): {packet['data']}\n")
                    f.write("-" * 80 + "\n\n")
            
            print(f"{Colors.GREEN}[SUCCESS] Packets saved to: {self.output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR] Failed to save file: {e}{Colors.END}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer - Capture and analyze network traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        ''')
    )
    
    parser.add_argument('-c', '--count', type=int, default=10,
                       help='Number of packets to capture (0 for infinite, default: 10)')
    parser.add_argument('-i', '--interface', type=str,
                       help='Network interface to capture on (optional)')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file to save captured packets')
    
    args = parser.parse_args()
    
    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        output_file=args.output
    )
    
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()