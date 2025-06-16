#         S-AES
#
# AddRoundKey (w0, w1)
# Rodada 1: 
#     - SubNibbles, 
#     - ShiftRows,
#     - MixColumns,
#     - AddRoundKey (w2, w3)
# Rodada 2:
#     - SubNibbles,
#     - ShiftRows,
#     - AddRoundKey (w4, w5)
# 

# Referências:
# https://docs.python.org/3/library/stdtypes.html#bitwise-operations-on-integer-types
# https://www.ime.usp.br/~rt/cranalysis/AESSimplified
# https://www.kopaldev.de/2023/09/17/simplified-aes-s-aes-cipher-explained-a-dive-into-cryptographic-essentials/
# https://en.wikipedia.org/wiki/Finite_field_arithmetic
# https://github.com/Glank/Galois/blob/master/examples.py


import base64

# S-Box fornecida convertida para hexadecimal
SBOX = [
    0x9, 0x4, 0xA, 0xB,  # 1001, 0100, 1010, 1011
    0xD, 0x1, 0x8, 0x5,  # 1101, 0001, 1000, 0101
    0x6, 0x2, 0x0, 0x3,  # 0110, 0010, 0000, 0011
    0xC, 0xE, 0xF, 0x7   # 1100, 1110, 1111, 0111
]

# Constantes de Rodada (Rcon)
CONSTANTE_RODADA = [0x80, 0x30]  # [10000000, 00110000]

# Função G: Rotaciona os nibbles, aplica a S-Box e XOR com a constante de rodada
def funcaoG(byte, constanteRodada):
    
    nibble1 = (byte >> 4) & 0xF   # & significa E bit a bit
    nibble2 = byte & 0xF
    
    # 1. Rot Word: Troca os nibbles de posição
    nibble1, nibble2 = nibble2, nibble1
    
    # 2. Sub Word: Aplica a S-Box em cada nibble
    primeiroNibble = SBOX[nibble1]
    segundoNibble = SBOX[nibble2]
    
    # 3. Aplica XOR com a constante de rodada (apenas no nibble mais significativo)
    primeiroNibble = primeiroNibble ^ (constanteRodada >> 4) & 0xF
    
    resultado = (primeiroNibble << 4) + segundoNibble      # 8 bits de resultado
    return resultado

#################
# Key Expansion #
#################

# Key Expansion: Expande a chave de 16 bits em 3 chaves de rodada (6 words de 8 bits)
def keyExpansion(chave):
    # Chave de 16 bits (4 nibbles) formam as 2 words iniciais w0 e w1
    bytesChave = chave.to_bytes(2, byteorder='big')
    w0 = bytesChave[0]  # Primeiro byte
    w1 = bytesChave[1]  # Segundo byte 
    
    # Primeira expansão para gerar w2 e w3
    # w2 = w0 xor g(w1) e w3 = w2 xor w1
    g1 = funcaoG(w1, CONSTANTE_RODADA[0])
    w2 = w0 ^ g1
    w3 = w2 ^ w1
    
    # Segunda expansão para gerar w4 e w5
    # w4 = w2 xor g(w3) e w5 = w4 xor w3
    g2 = funcaoG(w3, CONSTANTE_RODADA[1])
    w4 = w2 ^ g2
    w5 = w4 ^ w3
    
    # Retorna uma lista com as 3 chaves de rodada de 16 bits (Converte cada par de bytes em um inteiro de 16 bits)
    return [
        int.from_bytes(bytes([w0, w1]), byteorder='big'),
        int.from_bytes(bytes([w2, w3]), byteorder='big'),
        int.from_bytes(bytes([w4, w5]), byteorder='big')
    ]

#################################
# Tratamento de dados (passo 0) #
#################################

# Converte um bloco de 16 bits para a matriz de estado 2x2.
def blocoParaMatriz(valor):
    
    binario = f"{valor:016b}"
    lista = list(binario)
    
    matriz = [
        [''.join(lista[0:4]),  ''.join(lista[8:12])],   
        [''.join(lista[4:8]),  ''.join(lista[12:16])]   
    ]
    
    # Converte strings binárias para inteiros
    matriz = [[int(matriz[0][0], 2), int(matriz[0][1], 2)], 
            [int(matriz[1][0], 2), int(matriz[1][1], 2)]]

    return matriz

# Converte a matriz de estado 2x2 de volta para um bloco de 16 bits.
def matrixParaBloco(estado):
    # Converte cada nibble para string binária de 4 bits
    nibble0 = f"{estado[0][0]:04b}"  
    nibble1 = f"{estado[1][0]:04b}"  
    nibble2 = f"{estado[0][1]:04b}"  
    nibble3 = f"{estado[1][1]:04b}"  
    
    # Soma todos os nibbles em uma string binária de 16 bits
    bloco = nibble0 + nibble1 + nibble2 + nibble3
    
    # Converte o resultado para um bloco de 16 bits
    resultado = int(bloco, 2)
    return resultado

#############################
# Operações de rodada S-AES #
#############################

# SubNibbles: Recebe a matriz 2x2 e para cada nibble substitui na S-box
def subNibbles(estado):
    
    resultado = [[0, 0], [0, 0]]
    
    # Percorre cada linha da matriz
    for i in range(2):
        # Percorre cada nibble na linha
        for j in range(2):
            nibble = estado[i][j]
            nibbleNovo = SBOX[nibble]
            resultado[i][j] = nibbleNovo
    
    return resultado


# ShiftRows: Recebe a matriz 2x2 e inverte a segunda linha
def shiftRows(estado):
    
    resultado = [estado[0], [estado[1][1], estado[1][0]]]
    return resultado


# Multiplicação em GF(2^4) para MixColumns usando o polinômio irreducível x^4 + x + 1.
def galoisFields(a, b):
    
    resultado = 0
    
    # Como estamos em GF(2⁴), precisamos de 4 iterações (um para cada bit de b).
    for i in range(4): 
        
        # Se o bit menos significativo de b for 1, somamos (XOR) o valor atual de a ao resultado.
        if b & 1:
            resultado ^= a
            
        # Multiplica 'a' por x (deslocamento à esquerda)
        a <<= 1
        
        # Se a ultrapassou o limite de 4 bits (x⁴), fazemos uma redução 
        # usando o polinômio irreducível x⁴ + x + 1 (representado por 0b10011)
        if a & 0b10000:
            a ^= 0b10011 
        
        # Remove o bit processado de b
        b >>= 1
    
    return resultado & 0b1111


# Mix Columns: Opera em cada coluna individualmente. Multiplica cada coluna por uma matriz fixa [1, 4; 4, 1] em Galois Fields(16).
def mixColumns(estado):
    
    novoEstado = [[0, 0], [0, 0]]
    
    for i in range(2):
        # Coluna 0
        novoEstado[0][i] = galoisFields(1, estado[0][i]) ^ galoisFields(4, estado[1][i])
        # Coluna 1
        novoEstado[1][i] = galoisFields(4, estado[0][i]) ^ galoisFields(1, estado[1][i])
    return novoEstado


# Add Round Key: Aplica Xor bit a bit entre a matriz de estado e a chave da rodada.
def addRoundKey(estado, chaveRodada):
    
    resultado = [[0, 0], [0, 0]]
    chaveMatriz = blocoParaMatriz(chaveRodada)
 
    # Percorre cada linha
    for i in range(2):
        # Percorre cada coluna
        for j in range(2):  
            # Aplica XOR entre os elementos correspondentes
            resultado[i][j] = estado[i][j] ^ chaveMatriz[i][j]
    
    return resultado


######################
# S-AES Criptografia #
######################
def saes(plainText, chave):

    print("------------------------------------")
    print("          Saídas Intermediárias:")
    
    # 1. Gera as chaves de rodada a partir da chave
    chaveRodada = keyExpansion(chave)
    print(f"Chaves de rodada: {[f'{i:04x}' for i in chaveRodada]}")
    
    # 2. Converte o texto plano para o formato de matriz de estado
    estado = blocoParaMatriz(plainText)
    print(f"Texto plano em matriz: {estado}")
    
    # 3. Pré-rodada: AddRoundKey com a primeira chave
    estado = addRoundKey(estado, chaveRodada[0])
    print(f"Estado após AddRoundKey inicial: {estado}")
    print("------------------------------------")
    
    # 4. Rodada 1
    print("-> Rodada 1:")
    estado = subNibbles(estado)
    print(f"Estado após SubNibbles: {estado}")
    estado = shiftRows(estado)
    print(f"Estado após ShiftRows: {estado}")
    estado = mixColumns(estado)
    print(f"Estado após MixColumns: {estado}")
    estado = addRoundKey(estado, chaveRodada[1])
    print(f"Estado após AddRoundKey: {estado}")
    print("------------------------------------")
    
    # 5. Rodada 2 (Final - sem MixColumns)
    print("-> Rodada 2:")
    estado = subNibbles(estado)
    print(f"Estado após SubNibbles: {estado}")
    estado = shiftRows(estado)
    print(f"Estado após ShiftRows: {estado}")
    estado = addRoundKey(estado, chaveRodada[2])
    print(f"Estado após AddRoundKey: {estado}")
    print("------------------------------------")
    
    # 6. Converte o estado final de volta para um inteiro
    return matrixParaBloco(estado)


####################
#      Main        #
####################

if __name__ == "__main__":
    
    # Exemplo do uso do S-AES com uma chave e plaintext fornecidos
    chave = 0b1010011100111011  # 0xA73B
    plainText = 0b0110111101101011  # "ok" em ASCII (0x6F6B)
    resultadoEsperado = 0b0000011100111000  # 0x0738

    # Executa a criptografia chamando a função principal
    cipherText = saes(plainText, chave)
    
    # Mostra os resultados
    print("            Resultados:")
    print(f"Resultado esperado: {resultadoEsperado:016b}")
    print(f"Texto cifrado:      {cipherText:016b}")
    
    
    # Formatação da saída
    cifraBytes = cipherText.to_bytes(2, byteorder='big')
    print(f"Texto cifrado Hexadecimal: {cipherText:04x}")
    print(f"Texto cifrado Base64: {base64.b64encode(cifraBytes).decode('utf-8')}")