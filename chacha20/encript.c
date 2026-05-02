// Implementação do algoritmo ChaCha20 por Giovanni Schrickte Sartori para Iniciação Científica

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define CHACHA20_IMPLEMENTATION
#define CHUNK_SIZE 1024
#include "ChaCha20.h"

void hexdump(uint8_t* data, unsigned int len)
{
	char buff[17] = { '\0' };
	for(unsigned int i = 0; i < len; i++)
	{
		printf("%02x ", data[i]);
		buff[i % 16] = isprint(data[i]) ? data[i] : '.';

		if((i + 1) % 16 == 0)
			printf("   %s\n", buff);
	}

	printf("\x1b[52G%.*s\n", len % 16, buff);
}

int main(int argc, char* argv[]){

    struct timespec inicio, fim;
    double tempo_gasto;

    key256_t key = 
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    uint32_t count = 0x00000001;
    nonce96_t nonce = {0x00, 0x00, 0x00 , 0x00 , 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    uint8_t buffer[CHUNK_SIZE];
    memset(buffer, 0xAA, CHUNK_SIZE);

    ChaCha20_Ctx ctx;
    ChaCha20_init(&ctx, key, nonce, count);

    // Início do benchmarking

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &inicio);

    for(int i = 0; i < 1024; i++){
	ChaCha20_xor(&ctx, buffer, CHUNK_SIZE);
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &fim);

    tempo_gasto = (fim.tv_sec - inicio.tv_sec) + (fim.tv_nsec - inicio.tv_nsec) / 1e9;

    printf("%.9f\n", tempo_gasto);

    return 0;
}
