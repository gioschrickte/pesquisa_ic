#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "trivium.h"

#define CHUNK_SIZE 1024

int main(void)
{
    // Trivium utiliza chaves e IVs de 80 bits (10 bytes)
    uint8_t key[10] = {0};
    uint8_t iv[10]  = {0};

    // Alocação dos buffers na RAM
    uint8_t buffer[CHUNK_SIZE];
    uint8_t encbuffer[CHUNK_SIZE];
    
    // Limpeza da sujeira de memória e inserção do padrão fictício
    memset(buffer, 0xAA, CHUNK_SIZE);
    memset(encbuffer, 0x00, CHUNK_SIZE);

    struct timespec inicio, fim;
    double tempo_gasto;

    // Inicializa o contexto da cifra Trivium
    trivium_ctx* ctx = trivium_init(key, iv);

    // =========================================================
    // INÍCIO DO BENCHMARKING (ISOLAMENTO DE CPU)
    // =========================================================
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    // Loop externo: 1024 repetições para fechar exatos 1 MB
    for(int i = 0; i < CHUNK_SIZE; i++)
    {
        // Loop interno: Trivium gera e cifra 1 byte por vez
        for(int j = 0; j < CHUNK_SIZE; j++)
        {
            encbuffer[j] = buffer[j] ^ trivium_gen_keystream(ctx);
        }
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);
    // =========================================================

    // Calculo e impressão do tempo puro (para o script externo)
    tempo_gasto = (fim.tv_sec - inicio.tv_sec) + (fim.tv_nsec - inicio.tv_nsec) / 1e9;
    printf("%.9f\n", tempo_gasto);

    // Liberação de memória do contexto (se a sua biblioteca exigir free)
    // free(ctx);

    return 0;
}