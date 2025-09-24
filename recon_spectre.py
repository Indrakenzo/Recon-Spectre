# -*- coding: utf-8 -*-
# Recon-Spectre v2.0
# Instrumen Intelijen Digital oleh Indra-Jarvis

import socket
import whois
import requests
import dns.resolver
import shodan
from bs4 import BeautifulSoup
from termcolor import colored
import sys
import os
import threading
from queue import Queue

# ==============================================================================
# BANNER & TAMPILAN
# ==============================================================================
def bersihkan_layar():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = """
██████╗ ███████╗ ██████╗  ██████╗ ███╗   ██╗   ██████╗ ██████╗ ███████╗████████╗██████╗ ███████╗
██╔══██╗██╔════╝██╔═══██╗██╔═══██╗████╗  ██║   ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝
██████╔╝█████╗  ██║   ██║██║   ██║██╔██╗ ██║   ██████╔╝██████╔╝█████╗     ██║   ██████╔╝█████╗  
██╔══██╗██╔══╝  ██║   ██║██║   ██║██║╚██╗██║   ██╔══██╗██╔═══╝ ██╔══╝     ██║   ██╔══██╗██╔══╝  
██║  ██║███████╗╚██████╔╝╚██████╔╝██║ ╚████║██╗██║  ██║██║     ███████╗   ██║   ██║  ██║███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
                            Digital Intelligence Instrument
"""
    print(colored(banner, "blue", attrs=['bold']))
    print(colored("                              Oleh Indra-Jarvis\n", "cyan"))

# ==============================================================================
# MODUL-MODUL INTELIJEN
# ==============================================================================
def get_ip_and_whois(domain):
    print(colored("\n[+] Mengekstrak Informasi IP & WHOIS...", "yellow"))
    try:
        ip = socket.gethostbyname(domain)
        print(f"    {colored('Alamat IP', 'green')}      : {ip}")
        w = whois.whois(domain)
        print(f"    {colored('Registrar', 'green')}      : {w.registrar}")
        print(f"    {colored('Tanggal Dibuat', 'green')}  : {w.creation_date}")
        print(f"    {colored('Kedaluwarsa', 'green')}    : {w.expiration_date}")
    except Exception as e:
        print(colored(f"    [!] Gagal: {e}", "red"))

def get_dns_records(domain):
    print(colored("\n[+] Menginterogasi Catatan DNS...", "yellow"))
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"    {colored(f'Catatan {record_type}', 'green')}:")
            for rdata in answers:
                print(f"        -> {rdata.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            print(colored(f"    [!] Gagal mengambil catatan {record_type}: {e}", "red"))

def get_http_headers_and_links(domain):
    print(colored("\n[+] Menganalisis Target Web...", "yellow"))
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        print(f"    {colored('Status Kode', 'green')}    : {response.status_code}")
        server = response.headers.get('Server', 'Tidak Diketahui')
        print(f"    {colored('Server Web', 'green')}     : {server}")
        
        soup = BeautifulSoup(response.text, 'lxml')
        print(f"    {colored('Judul Halaman', 'green')}  : {soup.title.string.strip() if soup.title else 'Tidak ada'}")

        print(f"    {colored('Tautan Eksternal', 'green')}:")
        links_found = 0
        for link in soup.find_all('a', href=True):
            if 'http' in link['href'] and domain not in link['href']:
                print(f"        -> {link['href']}")
                links_found += 1
                if links_found >= 5: break # Batasi hingga 5 link
        if links_found == 0:
            print("        (Tidak ada)")
            
    except requests.RequestException as e:
        print(colored(f"    [!] Gagal terhubung ke https://{domain}: {e}", "red"))

def check_shodan(domain):
    # PENTING: Ganti 'YOUR_API_KEY' dengan kunci API Shodan Anda
    SHODAN_API_KEY = "YOUR_API_KEY"
    print(colored("\n[+] Menginterogasi Shodan...", "yellow"))
    if SHODAN_API_KEY == "YOUR_API_KEY":
        print(colored("    [!] Kunci API Shodan belum diatur. Melewati langkah ini.", "red"))
        return
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        ip = socket.gethostbyname(domain)
        host = api.host(ip)
        print(f"    {colored('Organisasi', 'green')}     : {host.get('org', 'n/a')}")
        print(f"    {colored('Sistem Operasi', 'green')}: {host.get('os', 'n/a')}")
        print(f"    {colored('Port Terbuka', 'green')}    :")
        for item in host['data']:
            print(f"        -> Port {item['port']}")
    except Exception as e:
        print(colored(f"    [!] Gagal mengambil data Shodan: {e}", "red"))


# ==============================================================================
# PROGRAM UTAMA
# ==============================================================================
if __name__ == "__main__":
    bersihkan_layar()
    print_banner()
    if len(sys.argv) != 2:
        print(colored("\nPenggunaan: python3 recon_spectre.py <domain.com>", "cyan"))
        sys.exit(1)
    
    target = sys.argv[1]
    print(colored(f"[*] Memulai Analisis Spektral untuk Target: {target}", "yellow", attrs=['bold']))
    print("="*80)
    
    # Menjalankan semua modul
    get_ip_and_whois(target)
    get_dns_records(target)
    get_http_headers_and_links(target)
    check_shodan(target)

    print("\n" + "="*80)
    print(colored("[*] Analisis Spektral Selesai.", "yellow", attrs=['bold']))