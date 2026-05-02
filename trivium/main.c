/* main_trivium.c
 *
 * Benchmark padronizado: cifra 1 MiB em chunks de 1 KiB e imprime
 * o tempo de CPU em segundos no stdout (formato %.9f\n).
 *
 * Cifra: Trivium (De Cannière & Preneel, eSTREAM submission)
 * Implementação de referência do designer, desenvelopada do envelope
 * C++ namespace do crocs-muni/CryptoStreams para C puro.
 *
 * Validação: o vetor de teste oficial "Set 1, vector # 0" foi
 * verificado contra o keystream esperado 38EB86FF730D7A9CAF8DF13A4420540D.
 *
 * Uso: ./trivium
 */

#define _POSIX_C_SOURCE 199309L  /* habilita clock_gettime e CLOCK_PROCESS_CPUTIME_ID */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "trivium.h"

#define CHUNK_SIZE  1024     /* 1 KiB */
#define NUM_CHUNKS  1024     /* 1024 * 1024 = 1 MiB */

int main(void)
{
    /* Trivium usa chave e IV de 80 bits (10 bytes) */
    u8 key[10] = {0};
    u8 iv[10]  = {0};

    static u8 buf_in [CHUNK_SIZE] __attribute__((aligned(16)));
    static u8 buf_out[CHUNK_SIZE] __attribute__((aligned(16)));

    memset(buf_in,  0xAA, CHUNK_SIZE);
    memset(buf_out, 0x00, CHUNK_SIZE);

    TRIVIUM_ctx ctx;
    TRIVIUM_keysetup(&ctx, key, 80, 80);
    TRIVIUM_ivsetup(&ctx, iv);

    /* ===== Início do benchmarking ===== */
    struct timespec inicio, fim;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    for (int i = 0; i < NUM_CHUNKS; i++) {
        TRIVIUM_encrypt_bytes(&ctx, buf_in, buf_out, CHUNK_SIZE);
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);
    /* ===== Fim do benchmarking ===== */

    double tempo_gasto = (fim.tv_sec - inicio.tv_sec)
                       + (fim.tv_nsec - inicio.tv_nsec) / 1e9;

    printf("%.9f\n", tempo_gasto);
    return 0;
}
