import sys
from scapy.all import *
from scapy.layers.inet import ICMP
import string
from colorama import Fore, Style

def load_spanish_dict():
    try:
        with open('diccionario.txt', 'r', encoding='utf-8') as f:
            return set(word.strip().lower() for word in f.readlines())
    except FileNotFoundError:
        print("Error: Archivo diccionario.txt no encontrado")
        sys.exit(1)

SPANISH_DICT = load_spanish_dict()

def extract_icmp_payloads(pcap_file):
    packets = rdpcap(pcap_file)
    messages = []
    
    for pkt in packets:
        if ICMP in pkt and pkt[ICMP].type == 8:  # Solo Echo requests
            payload = bytes(pkt[ICMP].payload)
            seq = pkt[ICMP].seq
            
            # Buscar el byte modificado (0x79)
            modified_pos = None
            for i, byte in enumerate(payload):
                if byte == 0x79:
                    modified_pos = i
                    break
            
            # Si encontramos 0x79 en posición 26 → espacio
            if modified_pos == 26:
                messages.append((seq, ' '))
            # Si encontramos 0x79 en otra posición → letra
            elif modified_pos is not None and modified_pos < 26:
                char = chr(modified_pos + ord('a'))
                messages.append((seq, char))
            # Si no hay 0x79 → ignorar el paquete
    
    # Ordenar por sequence number y reconstruir string
    messages.sort(key=lambda x: x[0])
    return ''.join([char for seq, char in messages])

def caesar_decrypt(ciphertext, shift):
    result = []
    for char in ciphertext:
        if char == ' ':
            result.append(' ')
        else:
            original_pos = ord(char) - ord('a')
            new_pos = (original_pos - shift) % 26
            result.append(chr(new_pos + ord('a')))
    return ''.join(result)

def is_spanish_word(word):
    return word.lower() in SPANISH_DICT

def analyze_possibilities(ciphertext):
    print("\nPosibles mensajes (César):")

    
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        words = decrypted.split()
        
        score = sum(1 for word in words if is_spanish_word(word))
        
        output = f"Shift {shift:2d}: {decrypted}"
        if score > 0:
            output = Fore.GREEN + output + Style.RESET_ALL
        print(output)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 decoder.py <captura.pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    ciphertext = extract_icmp_payloads(pcap_file)
    analyze_possibilities(ciphertext)