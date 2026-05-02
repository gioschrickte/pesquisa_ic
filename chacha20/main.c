/* main_chacha20.c
 *
 * Benchmark padronizado: cifra 1 MiB em chunks de 1 KiB e imprime
 * o tempo de CPU em segundos no stdout (formato %.9f\n).
 *
 * Cifra: ChaCha20 (D. J. Bernstein, eSTREAM submission, 20080118)
 * Implementação de referência merged, RFC 7539-compatível.
 *
 * Uso: ./chacha20
 */

#define _POSIX_C_SOURCE 199309L  /* habilita clock_gettime e CLOCK_PROCESS_CPUTIME_ID */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ecrypt-sync.h"

#define CHUNK_SIZE  1024     /* 1 KiB */
#define NUM_CHUNKS  1024     /* 1024 * 1024 = 1 MiB */

int main(void)
{
    /* Chave de 256 bits (zerada) e IV de 64 bits (zerado).
     * Conteúdo da chave/IV é irrelevante para benchmark de tempo
     * porque o ChaCha20 tem tempo constante em relação aos dados. */
    u8 key[32] = {0};
    u8 iv[8]   = {0};

    /* Buffers alinhados em 16 bytes para evitar penalidades em ARM */
    static u8 buf_in [CHUNK_SIZE] __attribute__((aligned(16)));
    static u8 buf_out[CHUNK_SIZE] __attribute__((aligned(16)));

    memset(buf_in,  0xAA, CHUNK_SIZE);
    memset(buf_out, 0x00, CHUNK_SIZE);

    ECRYPT_ctx ctx;
    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, 256, 64);
    ECRYPT_ivsetup(&ctx, iv);

    /* ===== Início do benchmarking ===== */
    struct timespec inicio, fim;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    for (int i = 0; i < NUM_CHUNKS; i++) {
        ECRYPT_encrypt_bytes(&ctx, buf_in, buf_out, CHUNK_SIZE);
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);
    /* ===== Fim do benchmarking ===== */

    double tempo_gasto = (fim.tv_sec - inicio.tv_sec)
                       + (fim.tv_nsec - inicio.tv_nsec) / 1e9;

    printf("%.9f\n", tempo_gasto);
    return 0;
}
