
import scapy.all as scapy


# Global variables for state management
log_messages = []
sniffing = False
selected_interface = ""

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answer_list:
        return answer_list[0][1].hwsrc
    else:
        return None



