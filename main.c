#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "SecLibs/evpTestes.c"
#include "SecLibs/geraChaves.c"
#include <time.h>

#define MAX_MSG 1024
#define QUANT_CRIP 4
char *vetCrip[QUANT_CRIP] = {"##AES256##", "##AES192##",
                             "##AES128##", "##CHACHA##"};
params_cifra *params;
char cripAtual[12];

void *tratador_conexao(void *);

int decrip(unsigned char *, unsigned char *, int);

void timerUltimaTroca(time_t, time_t *, int);

void gravaTemposComunicacao(unsigned long int, char *);


void timerUltimaTroca(time_t troca, time_t *fim, int qtdMensagens) {

    time_t now, gasto;
    time(&now);
    char *texto = "Tempo de execução da criptografia ";
    gasto = now - troca;
    printf("Timer: %ld/ inicio: %ld/ agora: %ld\n", gasto, troca, now);

    FILE *arq;
    // Acrescenta dados ou cria uma arquivo leitura e escrita.
    arq = fopen("./Tempos/tempos.txt", "a+");

    if (arq != NULL) {
        // escreve cada elemento do vetor no arquivo
        fflush(stdin);
        fprintf(arq, "Tempo de execução da criptografia %s :  %ld segundos\n", cripAtual, gasto);
        fprintf(arq, "Quantidade de Mensagens Recebidas: %d \n", qtdMensagens);

        //fecha o arquivo
        fclose(arq);
    } else {
        printf("\nErro ao abrir o arquivo para leitura!\n");
        exit(1); // aborta o programa
    }

    time(fim);

    // //Verificação a cada 1 min = 60 segundos
    // if(gasto > 60){
    //     //time(fim);
    //     printf("Inicio da Troca\n");
    //     return 1;
    // }
    //   return 0;
}


void trocaCrip(char *crip) {
    params_cifra *parametros = (params_cifra *) malloc(sizeof(params_cifra));
    params_cifra *varlimpar = params;
    if (strcmp(crip, vetCrip[0]) == 0) {
        parametros->chave = (unsigned char *) "01234567890123456789012345678901";
        parametros->iv = (unsigned char *) "UTF3456789012345";
        parametros->tipo_cifra = EVP_aes_256_cbc();
        strcpy(cripAtual, vetCrip[0]);
    } else if (strcmp(crip, vetCrip[1]) == 0) {
        /* A 192 bit chave */
        parametros->chave = (unsigned char *) "KKKKKKKK888985888582525T";
        parametros->iv = (unsigned char *) "BRA3456789012345";
        parametros->tipo_cifra = EVP_aes_192_cbc();
        strcpy(cripAtual, vetCrip[1]);
    } else if (strcmp(crip, vetCrip[2]) == 0) {
        /* A 128 bit chave */
        parametros->chave = (unsigned char *) "ARIAEFGHIJ123456";
        parametros->iv = (unsigned char *) "VOA3456789012345";
        parametros->tipo_cifra = EVP_aes_128_cbc();
        strcpy(cripAtual, vetCrip[2]);

    }else if (strcmp(crip, vetCrip[3]) == 0) {
        /* A 256 bit chave */
        parametros->chave = (unsigned char *) "01234567890123456789012345678901";
        parametros->iv = (unsigned char *) "VOA3456789012345";
        parametros->tipo_cifra = EVP_chacha20();
        strcpy(cripAtual, vetCrip[3]);

    }

    if (!params) {
        params = parametros;
        free(varlimpar);
    } else {
        params = parametros;
    }


    printf("Troca Realizada\n");
}

// void handleErrors(void)
// {
//     ERR_print_errors_fp(stderr);
//     abort();
// }

int decrip(unsigned char *textocifrado, unsigned char *textoclaro, int tamanho) {

//    printf("Texto Cifrado :\n");
//    BIO_dump_fp (stdout, (const char *)textocifrado, tamanho);

    int textoclaro_tamanho;

    /* Descifrando textocifrado */
    textoclaro_tamanho = decrypt(textocifrado, tamanho, params,
                                 textoclaro);

    textoclaro[textoclaro_tamanho] = '\0';

    /* Mostrando o texto claro */
//    printf("Texto Claro:\n");
//    printf("%s\n", textoclaro);

    return 0;

}

int imprimeCabecalho = 0;

void gravaTemposComunicacao(unsigned long int inicio, char *crip) {

    char *nomeArquivo = calloc(1, sizeof(char) * 20);
    // memset(nomeArquivo, 0, 20);
    strcpy(nomeArquivo, crip);
    strcat(nomeArquivo, ".csv");
    FILE *arquivo = fopen(nomeArquivo, "a+");
    if (arquivo) {
        // IMPRIMIR O CABECALHO DO ARQUIVO
        if (imprimeCabecalho == 0) {
            fprintf(arquivo, "\n %s ;", crip);
            imprimeCabecalho++;
        }

        time_t now, gasto;
        time(&now);
        gasto = now - inicio;

        fprintf(arquivo, "%ld ;", gasto);

    }
    fclose(arquivo);
    free(nomeArquivo);
}


int crip(unsigned char *textoclaro, unsigned char *textocifrado) {


    int textocifrado_tamanho;

    /* Criptografar o textoclaro */
    textocifrado_tamanho = encrypt(textoclaro, strlen((char *) textoclaro), params,
                                   textocifrado);

    /* Imprimindo texto cifrado */
    printf("Texto Cifrado :\n");
    BIO_dump_fp(stdout, (const char *) textocifrado, textocifrado_tamanho);

    return 0;
}


/*
 - Espera cliente conectar
 - Cria nova thread para o cliente
 - Envia mensagem de boas vindas para o cliente
 - Espera mensagem do cliente
 - Inicializa a troca de menssagens criptografadas
*/
void *tratador_conexao(void *conexao) {
    int sock = *(int *) conexao;
    int tamanho;
    char recebida[MAX_MSG];
    char *mensagem;
    char textoCifrado[MAX_MSG];
    // tempo_cifra * tempoAndTextoCifrado = malloc(sizeof(tempo_cifra));
    int deint = 0;
    int qtdMenssagens = 0;
    time_t inicio;

    //Enviando mensagem para o cliente
    mensagem = "Serv> Bem vindo.";
    write(sock, mensagem, strlen(mensagem));
    //Inicializando o tipo de criptografia a ser utilizada
    trocaCrip(vetCrip[0]);
    time(&inicio);
    fflush(stdin);
    while ((tamanho = recv(sock, textoCifrado, MAX_MSG, 0)) > 0) {
        qtdMenssagens++;
//        printf("Tamanho recebido %d \n", tamanho);
        memset(recebida, 0, MAX_MSG);
        while (decrip(textoCifrado, recebida, strlen(textoCifrado)) < 0) {
            fflush(stdout);
            write(sock, "##ERROR##", strlen("##ERROR##"));
        }
//        recebida[strlen(textoCifrado)] = '\0';

        // gravaTemposComunicacao(tempo, cripAtual);/
        printf("Recebida : %s\n", recebida);
        //verifica se na mensagem recebida contem a tag de troca de criptografia
        if (strcmp(recebida, vetCrip[0]) == 0
            || strcmp(recebida, vetCrip[1]) == 0
            || strcmp(recebida, vetCrip[2]) == 0
            || strcmp(recebida, vetCrip[3]) == 0) {
//            timerUltimaTroca( inicio, &inicio, qtdMenssagens);
            printf("\033[1;42m Iniciando a troca de Criptografia \033[0m\n");
            trocaCrip(recebida);
            fflush(stdin);
            write(sock, "##TROCAOK##", strlen("##TROCAOK##"));
            qtdMenssagens = 0;
        } else {
            fflush(stdout);
            write(sock, "##OK##", strlen("##OK##"));

        }

        // limpa as variaveis
        memset(textoCifrado, 0, MAX_MSG);
        memset(recebida, 0, MAX_MSG);
        fflush(stdin);

    }

    if (tamanho == 0) {
//        timerUltimaTroca( inicio, &inicio, qtdMenssagens);
        puts("Cliente desconectou.\n");
        fflush(stdout);
    } else if (tamanho == -1) {
        perror("erro no recebimento: \n Cliente Desconetado!\n ");
    }

    //Liberando o ponteiro
    free(conexao);

    return 0;
}

int main(void) {
    //variaveis
    int socket_desc, conexao, c, *nova_conexao;
    struct sockaddr_in server, client;
    char *mensagem;
    char resposta[MAX_MSG];
    int nbytes, count;

    // para pegar o IP e porta do cliente
    char *client_ip;
    int client_port;

    /*********************************************************/
    //Criando um socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Não foi possivel criar o socket\n");
        return -1;
    }

    int reuso = 1;
    if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuso, sizeof(reuso)) < 0) {
        perror("Não foi possivel reusar endereço");
        return -1;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEPORT, (const char *) &reuso, sizeof(reuso)) < 0) {
        perror("Não foi possível reusar porta");
        return -1;
    }
#endif

    //Preparando a struct do socket
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY; // Obtem IP do S.O.
    server.sin_port = htons(1234);
    //	printf("IP servidor : %s ", inet_ntoa(server.sin_addr));
    //Associando o socket a porta e endereco
    if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        puts("Erro ao fazer bind\n");
    }
    puts("Bind efetuado com sucesso\n");

    // Ouvindo por conexoes
    listen(socket_desc, 3);

    /*********************************************************/
    //Aceitando e tratando conexoes
    puts("Aguardando por conexoes...");
    c = sizeof(struct sockaddr_in);
    // Fica esperando por conexoes
    while ((conexao = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c))) {
        if (conexao < 0) {
            perror("Erro ao receber conexao\n");
            return -1;
        }
        // pegando IP e porta do cliente
        client_ip = inet_ntoa(client.sin_addr);
        client_port = ntohs(client.sin_port);
        printf("Cliente conectou: %s : [ %d ]\n", client_ip, client_port);

        /**** Criando thread para tratar da comunicacao ******/
        pthread_t processo;
        nova_conexao = malloc(1);
        *nova_conexao = conexao;

        if (pthread_create(&processo, NULL, tratador_conexao, (void *) nova_conexao) < 0) {
            perror("Nao foi possivel criar thread: ");
            return -1;
        }

    } //fim do while

    /*********************************************************/

    close(socket_desc);
    shutdown(socket_desc, 2);

    printf("Servidor finalizado...\n");
    return 0;
}