from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time

# Referência: https://techexpert.tips/pt-br/python-pt-br/python-usando-criptografia-aes/

KEY = b'chavesecretaparaencripta'  # 16 bytes (AES-128)
IV = get_random_bytes(16)    # IV de 16 bytes (para CBC/CFB/OFB)

def encrypt_AES(mode, data, key, iv=None):

    data = pad(data.encode('utf-8'), AES.block_size)
    
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
    
    elif mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
        cipher = AES.new(key, mode, iv=iv)
    
    elif mode == AES.MODE_CTR:
        cipher = AES.new(key, mode, nonce=iv[:8])  # Nonce de 8 bytes para CTR
    
    else:
        raise ValueError("Modo não suportado")

    ciphertext = cipher.encrypt(data)
    return base64.b64encode(ciphertext).decode('utf-8')


# Exemplo de uso para cada modo
plaintext = input("Insira aqui o plain Text: ")

# ECB
print("\nModo de operação: ECB")
start = time.time()
ecb = encrypt_AES(AES.MODE_ECB, plaintext, KEY)
end = time.time()
print(f"Texto cifrado ECB: {ecb} (Tempo: {end - start:.6f}s)\n")

# CBC
print("Modo de operação: CBC")
start = time.time()
cbc = encrypt_AES(AES.MODE_CBC, plaintext, KEY, IV)
end = time.time()
print(f"Texto cifrado CBC: {cbc} (Tempo: {end - start:.6f}s)\n")

# CFB
print("Modo de operação CFB")
start = time.time()
cfb = encrypt_AES(AES.MODE_CFB, plaintext, KEY, IV)
end = time.time()
print(f"Texto cifrado CFB: {cfb} (Tempo: {end - start:.6f}s)\n")

# OFB
print("Modo de operação OFB")
start = time.time()
ofb = encrypt_AES(AES.MODE_OFB, plaintext, KEY, IV)
end = time.time()
print(f"Texto cifrado OFB: {ofb} (Tempo: {end - start:.6f}s)\n")

# CTR 
print("Modo de operação CTR")
start = time.time()
ctr = encrypt_AES(AES.MODE_CTR, plaintext, KEY, IV)
end = time.time()
print(f"Texto cifrado CTR: {ctr} (Tempo: {end - start:.6f}s)\n")
