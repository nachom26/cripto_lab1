import sys

def cifrar_cesar(texto, desplazamiento):
    resultado = []
    for caracter in texto:
        if caracter.isupper():
            # Cifrar mayúsculas
            nuevo_caracter = chr((ord(caracter) + desplazamiento - 65) % 26 + 65)
            resultado.append(nuevo_caracter)
        elif caracter.islower():
            # Cifrar minúsculas
            nuevo_caracter = chr((ord(caracter) + desplazamiento - 97) % 26 + 97)
            resultado.append(nuevo_caracter)
        else:
            # Dejar otros caracteres sin cambios
            resultado.append(caracter)
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py [texto] [desplazamiento]")
        sys.exit(1)
    
    texto = sys.argv[1]
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("El desplazamiento debe ser un número entero")
        sys.exit(1)
    
    texto_cifrado = cifrar_cesar(texto, desplazamiento)
    print(texto_cifrado)