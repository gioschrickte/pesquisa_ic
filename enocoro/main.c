/* main_enocoro.c
 *
 * Benchmark padronizado: cifra 1 MiB em chunks de 1 KiB e imprime
 * o tempo de CPU em segundos no stdout (formato %.9f\n).
 *
 * Cifra: Enocoro-128v2 (Hitachi Systems Development Lab.)
 * Implementação de referência oficial em C, candidato CRYPTREC.
 *
 * NOTA SOBRE INTERFACE: ao contrário das outras três cifras que
 * adotam a interface eSTREAM (ECRYPT_*), a referência da Hitachi
 * expõe duas funções: ENOCORO_init() (key+iv setup combinado) e
 * ENOCORO_keystream() (gera keystream). Para cifrar, é necessário
 * fazer o XOR manualmente.
 *
 * CORREÇÃO em relação à versão anterior do código:
 *   o loop interno de XOR usava buf_arquivo[i] ^ buf_keystream[i]
 *   quando o índice correto é [j]. O bug fazia com que apenas o
 *   byte na posição i fosse repetidamente sobrescrito, ao invés
 *   de cifrar o chunk inteiro. O algoritmo Enocoro em si está
 *   intacto; apenas o harness de medição foi corrigido.
 *
 * Uso: ./enocoro
 */

#define _POSIX_C_SOURCE 199309L  /* habilita clock_gettime e CLOCK_PROCESS_CPUTIME_ID */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "enocoro.h"

#define CHUNK_SIZE  1024     /* 1 KiB */
#define NUM_CHUNKS  1024     /* 1024 * 1024 = 1 MiB */

int main(void)
{
    /* Enocoro-128v2: chave de 128 bits (16 bytes), IV de 64 bits (8 bytes) */
    uint8_t key[ENOCORO128_KEY_BYTE_SIZE] = {0};
    uint8_t iv[ENOCORO_IV_BYTE_SIZE]      = {0};

    static uint8_t buf_in [CHUNK_SIZE] __attribute__((aligned(16)));
    static uint8_t buf_out[CHUNK_SIZE] __attribute__((aligned(16)));
    static uint8_t buf_ks [CHUNK_SIZE] __attribute__((aligned(16)));

    memset(buf_in,  0xAA, CHUNK_SIZE);
    memset(buf_out, 0x00, CHUNK_SIZE);

    ENOCORO_Ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ENOCORO_init(&ctx, key, ENOCORO128_KEY_BYTE_SIZE,
                 iv, ENOCORO_IV_BYTE_SIZE);

    /* ===== Início do benchmarking ===== */
    struct timespec inicio, fim;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    for (int i = 0; i < NUM_CHUNKS; i++) {
        /* Gera CHUNK_SIZE bytes de keystream */
        ENOCORO_keystream(&ctx, buf_ks, CHUNK_SIZE);

        /* XOR byte-a-byte (note: índice j, não i — bug corrigido) */
        for (size_t j = 0; j < CHUNK_SIZE; j++) {
            buf_out[j] = buf_in[j] ^ buf_ks[j];
        }
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);
    /* ===== Fim do benchmarking ===== */

    double tempo_gasto = (fim.tv_sec - inicio.tv_sec)
                       + (fim.tv_nsec - inicio.tv_nsec) / 1e9;

    printf("%.9f\n", tempo_gasto);
    return 0;
}
