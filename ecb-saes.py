from saes import saes
import base64

###################################
#  Modo de Operação ECB com S-AES #
###################################

# OBS: A mensagem de entrada para o modo ECB (sem padding) deve ter um tamanho múltiplo de 2 bytes.
def encrypt_saes_ecb(texto, chave):
    
    tamanhoBloco = 2  # O S-AES opera em blocos de 2 bytes
    blocosCifrados = []
    # Divide a mensagem em blocos de 2 bytes
    for i in range(0, len(texto), tamanhoBloco):
        
        bytes = texto[i:i+tamanhoBloco]
        
        # Converte o bloco de bytes para um inteiro para a função saes()
        plainText = int.from_bytes(bytes.encode('utf-8'), 'big')
        
        # Criptografa cada bloco de forma independente
        cifrado = saes(plainText, chave)
        print(f"Texto cifrado cifrado: {cifrado:016b}")
        print("------------------------------------")
        blocosCifrados.append(format(cifrado, '016b'))
        
    return blocosCifrados


a = input("Digite a chave (4 bits hexadecimais): ")
b = input("Digite o texto em claro (a quantidade de caracteres precisa ser par): ")

chave = int(a, 16)

# Implementação do modo de Operação ECB:
cipherTextEcb = encrypt_saes_ecb(b, chave) 
print(" \n-> Texto cifrado com Modo de Operação ECB:")
print(f"Lista de blocos cifrados: {cipherTextEcb}\n")
print("Formatação de cada elemento da lista de blocos cifrados:\n")

# Formatação da saída ECB
for i in cipherTextEcb:
    blocoInt = int(i, 2)
    cifraBytes = blocoInt.to_bytes(2, byteorder='big')
    print(f"Texto cifrado bináro: {i}")
    print(f"Texto cifrado Base64: {base64.b64encode(cifraBytes).decode('utf-8')}")
    print(f"Texto cifrado em Hexadecimal: {blocoInt:04x}")
    print("------------------------------------")




