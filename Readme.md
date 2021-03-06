# ServidorSistema 
Servidor desenvolvido para realizar a troca de mensagens com clientes, 
garantindo a confidencialidade das mensagens utilizando criptografias simétricas.
### Criptografias Utilizadas
    - AES 128 a 256bits e modo de criptografia CBC (Cypher Block Chaining - Criptografia de Blocos Encadeados)
    - BlowFish 128 a 256bits e modo de criptografia CBC (Cypher Block Chaining - Criptografia de Blocos Encadeados)
### Pré-Requisito
Para executar o projeto, será necessário instalar os seguintes programas:

- [openssl-1.1.+ : Necessário para executar os processos de criptografias](https://www.openssl.org/source/)

### Construir o executável 
Acessar a pasta do projeto pelo terminal, executar o seguinte comando:
```shell
  cd ServidorSistema/
  make compile
```

### Executar o projeto
Já na pasta do projeto pelo terminal, executar o seguinte comando:
```shell
  make run
```

### Realizou modificações no projeto?
Acessar a pasta principal pelo terminal, executar o seguinte comando:
```shell
  cd ServidorSistema/
  make clean
```
E realize novamente o processo de construção do executável.
