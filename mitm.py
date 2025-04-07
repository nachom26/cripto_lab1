import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import string
from colorama import Fore, Style
import signal
import time

# Variable global para controlar el bucle
sniffing = True

def signal_handler(sig, frame):
    """Maneja la señal de interrupción (Ctrl+C) para detener el sniffing."""
    global sniffing
    print(f"\n{Fore.YELLOW}[!] Deteniendo el sniffer...{Style.RESET_ALL}")
    sniffing = False

def load_dictionary(dict_path):
    """Carga el diccionario español desde un archivo txt."""
    try:
        with open(dict_path, 'r', encoding='utf-8') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Archivo de diccionario no encontrado en {dict_path}{Style.RESET_ALL}")
        return None

def decrypt_cesar(ciphertext, shift):
    """Descifra un texto cifrado con César."""
    result = []
    for char in ciphertext:
        if char in string.ascii_lowercase:
            new_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            result.append(new_char)
        else:
            result.append(char)
    return ''.join(result)

def is_meaningful(text, dictionary):
    """Verifica si el texto contiene palabras del diccionario."""
    if not dictionary:
        return False
    words = text.lower().split()
    return any(word in dictionary for word in words if len(word) > 1)  # Ignorar palabras de 1 letra

def process_packet(packet):
    """Procesa paquetes ICMP para extraer caracteres."""
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        payload = bytes(packet[ICMP].payload)
        if len(payload) >= 32:
            if len(payload) > 26 and payload[26] == 0x79:
                return ' '
            for i, byte in enumerate(payload):
                if byte == 0x79 and i < 26:  # Solo considerar posiciones 0-25 para letras
                    return chr(ord('a') + i)
    return None

def main():
    global sniffing
    dict_path = "diccionario.txt"  # Asegúrate de que esté en la misma carpeta
    spanish_dict = load_dictionary(dict_path)
    
    if not spanish_dict:
        print(f"{Fore.RED}[-] Saliendo...{Style.RESET_ALL}")
        return

    print(f"{Fore.YELLOW}[*] Iniciando sniffer ICMP (Ctrl+C para detener)...{Style.RESET_ALL}")
    captured_chars = []
    
    def packet_callback(packet):
        if not sniffing:
            return
        char = process_packet(packet)
        if char is not None:
            captured_chars.append(char)
            current_text = ''.join(captured_chars)
            print(f"{Fore.CYAN}[+] Texto parcial: {current_text}{Style.RESET_ALL}", end='\r', flush=True)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    while sniffing:
        sniff(filter="icmp and icmp[0] == 8", prn=packet_callback, store=0, timeout=1)
    
    print("\n")  # Salto de línea tras Ctrl+C
    
    if not captured_chars:
        print(f"{Fore.RED}[-] No se capturaron paquetes válidos.{Style.RESET_ALL}")
        return
    
    ciphertext = ''.join(captured_chars)
    print(f"{Fore.YELLOW}[*] Mensaje cifrado completo: {ciphertext}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[*] Probando desplazamientos César:{Style.RESET_ALL}")
    for shift in range(26):
        decrypted = decrypt_cesar(ciphertext, shift)
        if is_meaningful(decrypted, spanish_dict):
            print(f"{Fore.GREEN}[✓] Shift {shift:2d}: {decrypted} (COINCIDENCIA){Style.RESET_ALL}")
        else:
            print(f"[ ] Shift {shift:2d}: {decrypted}")

if __name__ == "__main__":
    main()