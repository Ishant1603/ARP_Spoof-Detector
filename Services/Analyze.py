from Checking import *
import scapy.all as scapy

def process_sniffed_packet(packet):
    global log_messages
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        real_mac = get_mac(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc

        if real_mac and real_mac != response_mac:
            log_messages.append(f"ALERT! ARP spoofing detected!")
            log_messages.append(f"Real MAC: {real_mac}, Fake MAC: {response_mac}")


def sniff(interface):
    global sniffing
    sniffing = True
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, stop_filter=lambda x: not sniffing)