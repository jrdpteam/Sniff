import os
import sys
import json
import time
import scapy.all as scapy
import ipaddress
import socket
import keyboard
import colorama
import subprocess
from colorama import Fore, Style, init
from scapy.all import *





def main():
    os.system("clear")
    ascii_art()
    print("\n")
    os.system("sudo airmon-ng")
    interface = input(f"{Fore.MAGENTA}Select interface: {Style.RESET_ALL}")

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_type = "Unknown"

            if TCP in packet:
                packet_type = "TCP"
            elif UDP in packet:
                packet_type = "UDP"
            elif ICMP in packet:
                packet_type = "ICMP"
            elif DNS in packet:
                packet_type = "DNS"
            elif ARP in packet:
                packet_type = "ARP"

            print(f"Source IP: {Fore.CYAN}{src_ip:<15}{Style.RESET_ALL} {Fore.WHITE}|{Style.RESET_ALL} Destination IP: {Fore.RED}{dst_ip:<15}{Style.RESET_ALL}  {Fore.WHITE}|{Style.RESET_ALL} Packet Type: {Fore.BLUE}{packet_type}{Style.RESET_ALL}")

            with open('outputs/packets.txt', 'a') as file:
                file.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Packet Type: {packet_type}\n")

    sniff_menu_options(interface, packet_callback)

def get_hostname_from_ip(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def sniff_and_convert(interface):
    def packet_callback_with_conversion(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_type = "Unknown"

            if TCP in packet:
                packet_type = "TCP"
            elif UDP in packet:
                packet_type = "UDP"
            elif ICMP in packet:
                packet_type = "ICMP"
            elif DNS in packet:
                packet_type = "DNS"
            elif ARP in packet:
                packet_type = "ARP"

            src_hostname = get_hostname_from_ip(src_ip)
            dst_hostname = get_hostname_from_ip(dst_ip)

            dst_url = get_url_from_ip(dst_ip)

            if dst_url:
                print(f"Source IP/Hostname: {Fore.CYAN}{src_hostname or src_ip:<15}{Style.RESET_ALL} {Fore.WHITE}|{Style.RESET_ALL} Destination URL: {Fore.GREEN}{dst_hostname or dst_url}{Style.RESET_ALL}  {Fore.WHITE}|{Style.RESET_ALL} Packet Type: {Fore.BLUE}{packet_type}{Style.RESET_ALL}")

                with open('outputs/packets_with_conversion.txt', 'a') as file:
                    file.write(f"Source IP/Hostname: {src_hostname or src_ip}, Destination URL: {dst_hostname or dst_url}, Packet Type: {packet_type}\n")

    sniff(iface=interface, prn=packet_callback_with_conversion, store=0)

def get_url_from_ip(ip_address):
    try:
        url = os.popen(f"curl -sI {ip_address} | grep -i 'location\|uri' | awk '{{print $2}}'").read().strip()
        return url if url else None
    except Exception as e:
        print(f"Error retrieving URL: {e}")
        return None

def sniff_menu_options(interface, packet_callback):
    while True:
        os.system("clear")
        ascii_art()
        print("\n1. Regular Sniffing")
        print("2. Sniffing with IP to URL Conversion")
        print("3. Back to Main Menu")

        choice = input(f"{Fore.MAGENTA}Enter your choice: {Style.RESET_ALL}")

        if choice == "1":
            sniff(iface=interface, prn=packet_callback, store=0)
        elif choice == "2":
            sniff_and_convert(interface)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please enter a valid option.")








def ascii_art():
    colorama.init(autoreset=True)
    ascii_art = colorama.Fore.RED + """
    ██████    ███▄    █  ██▓  █████▒ █████▒
   ▒██    ▒  ██ ▀█   █ ▓██▒▓ ██    ▓██   ▒ 
   ░ ▓██▄   ▓██  ▀█ ██▒ ██▒ ▒████ ░ ████ ░ 
     ▒   ██ ▓██▒  ▐▌██ ░██░░ ▓█▒  ░░▓█▒  ░ 
   ▒██████▒ ▒██░   ▓██░ ██░ ░▒█░   ░▒█░ 
   ▒ ▒▓▒ ▒ ░░ ▒░v4.0▒ ▒ ░▓   ▒ ░    ▒ ░ 
   ░ ░▒  ░ ░░ ░░   ░ ▒░ ▒ ░ ░      ░  
   ░  ░by░JRDP ░ Team░  ▒ ░ ░ ░    ░ ░ 
         ░           ░  ░
    """ + colorama.Style.RESET_ALL
    print(ascii_art)










if __name__ == "__main__":
    main()

