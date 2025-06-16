# S-AES
Repositório para o trabalho 2 da disciplina de Segurança Computacional - UnB

Nome: Sofia Dy La Fuente Monteiro
Matrícula: 211055530

-----

### Parte I (saes):
Para a execução da parte 1, podem ser feitas de duas maneiras:
- Execução normal do programa, com a chave de teste 0b1010011100111011  ( Ou 0xA73B ) e o plain Text de 0b0110111101101011  ("ok" em ASCII (0x6F6B));
- Execução customizada com valores inseridos.

Para a segunda opção é necessário comentar as partes do código especificadas (Linhas: 260, 261 e 272) e descomentar as outras linhas especificadas (Linhas 264 e 265)


### Parte II (ecb-saes):
Para a execução da parte 2 é necessário que:
- A chave seja especificada em 4 bits hexadecimais;
- O texto em clado tenha tamanho par.

### Parte III (aes):
Para a execução da parte 3 é necessário instalar as seguintes dependências:
```bash
pip install pycryptodome
```
