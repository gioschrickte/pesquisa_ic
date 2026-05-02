#include <time.h>

#include "ecrypt-sync.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#define CHUNK_SIZE 1024

void print_hex(const char *tag, uint8_t *arg, int len) {
    printf("%12s: ", tag);    
    for (int i = 0; i < len; i++) printf("%02X ", arg[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    
    struct timespec inicio, fim;
    double tempo_gasto;
	int i = 0;

    uint8_t key[16] = {0};
    uint8_t iv[8] = {0};    

    ECRYPT_ctx ctx;    

    uint8_t buf_in[CHUNK_SIZE];
    uint8_t buf_out[CHUNK_SIZE];

    memset(buf_in, 0xAA, CHUNK_SIZE);
    memset(buf_out, 0x00, CHUNK_SIZE);

    int bytes_lidos = CHUNK_SIZE;

    ECRYPT_keysetup(&ctx, key, 128, 64);
    ECRYPT_ivsetup(&ctx, iv);

    // Inicio do Benchmarking
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    for(int i = 0; i < 1024; i++) {
        // recebe o In, joga pro Out e já faz o XOR
        ECRYPT_encrypt_bytes(&ctx, buf_in, buf_out, bytes_lidos);
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);

    // Calculo e impressão do tempo
    tempo_gasto = (fim.tv_sec - inicio.tv_sec) + (fim.tv_nsec - inicio.tv_nsec) / 1e9;
    printf("%.9f\n", tempo_gasto);

    return 0;
}


