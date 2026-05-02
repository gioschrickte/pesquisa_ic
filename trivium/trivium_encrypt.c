#include <stdio.h>
#include <time.h>

#include "utils.h"
#include <trivium.h>

#define CHUNK_SIZE 1024

uint8_t get_random_byte()
{
    return (uint8_t) (rand() % 256);
}

uint8_t hexchar_to_int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;

    return -1;
}

uint8_t get_byte_from_console_input()
{
    uint8_t rb;
    uint8_t hc1, hc2;
    scanf("%c%c", &hc1, &hc2);
    rb = (hexchar_to_int(hc1) << 4) | (hexchar_to_int(hc2) );
    return rb;
}

int main(int argc, char **argv)
{
    uint8_t key[10], iv[10];

    uint8_t buffer[CHUNK_SIZE], encbuffer[CHUNK_SIZE];
    memset(buffer, 0xAA, CHUNK_SIZE);

    struct timespec inicio, fim;
    double tempo_gasto;
    int i = 0;

    // Initialize the key and the IV
    srand(time(NULL));

    for(i = 0; i < 10; i++)
    {
        key[i] = get_random_byte();
        iv[i] = get_random_byte();
    }

    // Initialize the trivium cipher
    trivium_ctx* ctx = trivium_init(key, iv);

    // INICIO BENCHMARKING
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    // Encrypt the file
    while(fread(&buffer, 1, 1, pFile) != 0)
    {
        encbuffer = buffer ^ trivium_gen_keystream(ctx);
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);

    // Calculo e impressão do tempo
    tempo_gasto = (fim.tv_sec - inicio.tv_sec) + (fim.tv_nsec - inicio.tv_nsec) / 1e9;
    printf("%.9f\n", tempo_gasto);
    

    return 0;
}
