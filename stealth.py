import sys
from scapy.all import *
import string
import time  # Importamos time para el sleep

def generate_payload(offset):
    # Genera el payload inicial (a-w en hexadecimal: 61-77)
    hex_values = [0x61 + i for i in range(0x77 - 0x61 + 1)]  # 61-77 (a-w)
    payload = hex_values.copy()
    
    # Repetir hasta alcanzar 32 bytes
    while len(payload) < 32:
        payload.extend(hex_values)
    payload = payload[:32]  # Asegurar 32 bytes
    
    # Si offset es None (espacio), poner 0x79 en posición 27 (índice 26)
    if offset is None:
        if len(payload) > 26:  # Aseguramos que existe la posición 27
            payload[26] = 0x79
    elif offset < len(payload):  # Letra normal
        payload[offset] = 0x79
    
    return bytes(payload)

def send_icmp_packets(text):
    target_ip = "142.251.0.101"
    text_lower = text.lower()
    seq_num = 1
    
    for char in text_lower:
        if char == ' ':  # Si es espacio, offset=None (se pondrá 0x79 en posición 27)
            offset = None
        elif char in string.ascii_lowercase:
            offset = ord(char) - ord('a')
        else:  # Si no es letra ni espacio, ignorar
            continue
            
        payload = generate_payload(offset)
        packet = IP(dst=target_ip)/ICMP(
            type=8,  # Echo request
            code=0,
            id=1,    # BE=1, LE=256
            seq=seq_num  # Sequence number (incremental)
        )/payload
        
        send(packet, verbose=0)
        print(f"Sent 1 packet.")
        seq_num += 1
        time.sleep(1)  # Pequeña pausa entre paquetes

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 stealth.py [texto]")
        sys.exit(1)
    
    text = sys.argv[1]
    send_icmp_packets(text)