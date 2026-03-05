#include "ecrypt-sync.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#define CHUNK_SIZE 4096

void print_hex(const char *tag, uint8_t *arg, int len) {
    printf("%12s: ", tag);    
    for (int i = 0; i < len; i++) printf("%02X ", arg[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    FILE* file_in = fopen("in.bin", "rb");
    FILE* file_out = fopen("out.bin", "wb");

    if(file_in == NULL || file_out == NULL){
        printf("Erro na abertura dos arquivos\n");
        return 1;
    }
    

    uint8_t key[16] = {0};
    uint8_t iv[8] = {0};    

    ECRYPT_ctx ctx;    

    uint8_t buf_in[CHUNK_SIZE];
    uint8_t buf_out[CHUNK_SIZE];
    size_t bytes_lidos;

    ECRYPT_keysetup(&ctx, key, 16, 8);
    ECRYPT_ivsetup(&ctx, iv);

    printf("Iniciando criptografia com Rabbit...\n");

    while ((bytes_lidos = fread(buf_in, 1, CHUNK_SIZE, file_in)) > 0) {
        
        // recebe o In, joga pro Out e já faz o XOR
        ECRYPT_encrypt_bytes(&ctx, buf_in, buf_out, bytes_lidos);

        // Escreve os bytes já encriptados (que estão no buf_out) para o disco
        fwrite(buf_out, 1, bytes_lidos, file_out);
    }

    fclose(file_in);
    fclose(file_out);

    printf("Processamento concluído com sucesso!\n");
    return 0;
}


