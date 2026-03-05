/****************************************************/
/* Systems Development Lab., Hitachi, Ltd.          */
/* Rev.1.0                                          */
/* 2 February 2010                                  */
/* (c) Hitachi, Ltd. 2010. All rights reserved.     */
/****************************************************/
/**

 *
 */
#include <stdio.h>
#include <string.h>
#include "enocoro.h"


/**
 * MACRO
 */
#define K128_1     2
#define K128_2     7
#define K128_3     16
#define K128_4     29
#define K128_P1    6
#define K128_P2    15
#define K128_P3    28
#define K128_SHIFT 31
#define TEST_VECTOR_BYTE_SIZE 1024


/**
 * update state
 */
#define ENOCORO_NEXT128(state, buffer)\
{\
	/* copy state */\
	tmp[0] = state[0];\
	/* update state (σ-Function) */\
	tmp[1] = state[0] ^ Sbox[buffer.b[(K128_1 + buffer.top) & 0x1f]];\
	tmp[2] = state[1] ^ Sbox[buffer.b[(K128_2 + buffer.top) & 0x1f]];\
	state[0] = tmp[1] ^ tmp[2] ^ Sbox[buffer.b[(K128_3 + buffer.top) & 0x1f]];\
	state[1] = tmp[1] ^ xtime[tmp[2]] ^ Sbox[buffer.b[(K128_4 + buffer.top) & 0x1f]];\
	/* update buffer (λ-Function) */\
	buffer.b[(K128_1 + buffer.top) & 0x1f] ^= buffer.b[(K128_P1 + buffer.top) & 0x1f];\
	buffer.b[(K128_2 + buffer.top) & 0x1f] ^= buffer.b[(K128_P2 + buffer.top) & 0x1f];\
	buffer.b[(K128_3 + buffer.top) & 0x1f] ^= buffer.b[(K128_P3 + buffer.top) & 0x1f];\
	buffer.top = (buffer.top + K128_SHIFT) & 0x1f;\
	buffer.b[buffer.top] ^= tmp[0];\
}


/**
 * Xtime table
 */
static const uint8_t xtime[] =
{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
	0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
	0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	0x1d, 0x1f, 0x19, 0x1b, 0x15, 0x17, 0x11, 0x13,
	0x0d, 0x0f, 0x09, 0x0b, 0x05, 0x07, 0x01, 0x03,
	0x3d, 0x3f, 0x39, 0x3b, 0x35, 0x37, 0x31, 0x33,
	0x2d, 0x2f, 0x29, 0x2b, 0x25, 0x27, 0x21, 0x23,
	0x5d, 0x5f, 0x59, 0x5b, 0x55, 0x57, 0x51, 0x53,
	0x4d, 0x4f, 0x49, 0x4b, 0x45, 0x47, 0x41, 0x43,
	0x7d, 0x7f, 0x79, 0x7b, 0x75, 0x77, 0x71, 0x73,
	0x6d, 0x6f, 0x69, 0x6b, 0x65, 0x67, 0x61, 0x63,
	0x9d, 0x9f, 0x99, 0x9b, 0x95, 0x97, 0x91, 0x93,
	0x8d, 0x8f, 0x89, 0x8b, 0x85, 0x87, 0x81, 0x83,
	0xbd, 0xbf, 0xb9, 0xbb, 0xb5, 0xb7, 0xb1, 0xb3,
	0xad, 0xaf, 0xa9, 0xab, 0xa5, 0xa7, 0xa1, 0xa3,
	0xdd, 0xdf, 0xd9, 0xdb, 0xd5, 0xd7, 0xd1, 0xd3,
	0xcd, 0xcf, 0xc9, 0xcb, 0xc5, 0xc7, 0xc1, 0xc3,
	0xfd, 0xff, 0xf9, 0xfb, 0xf5, 0xf7, 0xf1, 0xf3,
	0xed, 0xef, 0xe9, 0xeb, 0xe5, 0xe7, 0xe1, 0xe3
};


/**
 * Sbox table
 */
static const uint8_t Sbox[256] =
{
	99, 82, 26, 223, 138, 246, 174, 85,
	137, 231, 208, 45, 189, 1, 36, 120,
	27, 217, 227, 84, 200, 164, 236, 126,
	171, 0, 156, 46, 145, 103, 55, 83,
	78, 107, 108, 17, 178, 192, 130, 253,
	57, 69, 254, 155, 52, 215, 167, 8,
	184, 154, 51, 198, 76, 29, 105, 161,
	110, 62, 197, 10, 87, 244, 241, 131,
	245, 71, 31, 122, 165, 41, 60, 66,
	214, 115, 141, 240, 142, 24, 170, 193,
	32, 191, 230, 147, 81, 14, 247, 152,
	221, 186, 106, 5, 72, 35, 109, 212,
	30, 96, 117, 67, 151, 42, 49, 219,
	132, 25, 175, 188, 204, 243, 232, 70,
	136, 172, 139, 228, 123, 213, 88, 54,
	2, 177, 7, 114, 225, 220, 95, 47,
	93, 229, 209, 12, 38, 153, 181, 111,
	224, 74, 59, 222, 162, 104, 146, 23,
	202, 238, 169, 182, 3, 94, 211, 37,
	251, 157, 97, 89, 6, 144, 116, 44,
	39, 149, 160, 185, 124, 237, 4, 210,
	80, 226, 73, 119, 203, 58, 15, 158,
	112, 22, 92, 239, 33, 179, 159, 13,
	166, 201, 34, 148, 250, 75, 216, 101,
	133, 61, 150, 40, 20, 91, 102, 234,
	127, 206, 249, 64, 19, 173, 195, 176,
	242, 194, 56, 128, 207, 113, 11, 135,
	77, 53, 86, 233, 100, 190, 28, 187,
	183, 48, 196, 43, 255, 98, 65, 168,
	21, 140, 18, 199, 121, 143, 90, 252,
	205, 9, 79, 125, 248, 134, 218, 16,
	50, 118, 180, 163, 63, 68, 129, 235
};


#ifdef PRINT_INTER
void print_ctx(ENOCORO_Ctx *ctx, int round);
#endif	/* PRINT_INTER */

/**
 * initiarize context
 */
void ENOCORO_init(ENOCORO_Ctx *ctx, const uint8_t *key, uint32_t keysize,
		const uint8_t *iv, uint32_t ivsize)
{
	uint32_t i = 0;
	uint8_t tmp[3];		/* use ENOCORO_NEXT */
	uint8_t ctr = 1;

#ifdef PRINT_INTER
		printf("ENOCORO_init internal values\n");
#endif	/* PRINT_INTER */

	/* cpoy context */
	memcpy(ctx->key, key, keysize);
	ctx->keysize = keysize;
	ctx->ivsize = ivsize;

	/* copy IV */
	memcpy(ctx->state.iv, iv, ENOCORO_IV_BYTE_SIZE);

	/* set key */
	for (i = 0; i < ctx->keysize; i++) {
		ctx->state.buffer.b[i] = ctx->key[i];
	}

	/* set IV */
	for (i = 0; i < ctx->ivsize; i++) {
		ctx->state.buffer.b[ctx->keysize + i] = ctx->state.iv[i];
	}

	/* set constant */
	ctx->state.buffer.top = 0;
	ctx->state.buffer.size = ENOCORO128_BUFFER_BYTE_SIZE;
	ctx->state.buffer.b[24] = 0x66;
	ctx->state.buffer.b[25] = 0xe9;
	ctx->state.buffer.b[26] = 0x4b;
	ctx->state.buffer.b[27] = 0xd4;
	ctx->state.buffer.b[28] = 0xef;
	ctx->state.buffer.b[29] = 0x8a;
	ctx->state.buffer.b[30] = 0x2c;
	ctx->state.buffer.b[31] = 0x3b;
	ctx->state.a[0] = 0x88;
	ctx->state.a[1] = 0x4c;

#ifdef PRINT_INTER
		print_ctx(ctx, -(INIT_ROUND_NUM_128 + 1));
#endif	/* PRINT_INTER */

	/* round = -96(VER2) step 1 to 0  */
	for (i = 0; i < INIT_ROUND_NUM_128; i++) {
		ctx->state.buffer.b[(ctx->state.buffer.top + K128_SHIFT) & 0x1f] ^= ctr;
		ctr = xtime[ctr];
		ENOCORO_NEXT128(ctx->state.a, ctx->state.buffer);
#ifdef PRINT_INTER
		print_ctx(ctx, i - INIT_ROUND_NUM_128);
#endif	/* PRINT_INTER */
	}
}


/**
 * create randum value
 */
void ENOCORO_keystream(ENOCORO_Ctx *ctx, uint8_t *keystream, uint32_t length)
{
	uint8_t tmp[3];		/* use ENOCORO_NEXT */
#ifdef PRINT_INTER
	int i = 0;

	printf("ENOCORO_keystream internal values\n");
#endif  /* PRINT_INTER */

	/* create randum value */
	while(length--) {
		/* get randum value */
		*keystream++ = ctx->state.a[1];
		/* update state */
		ENOCORO_NEXT128(ctx->state.a, ctx->state.buffer);
#ifdef PRINT_INTER
		print_ctx(ctx, i);
		i++;
#endif	/* PRINT_INTER */
	}
}

#ifdef PRINT_INTER
void print_ctx(ENOCORO_Ctx *ctx, int round)
{
	int i;

	printf("round = %d\n", round);
	printf("state : %02x %02x\n",ctx->state.a[0], ctx->state.a[1]);
	printf("buffer : ");
	printf("%02x", ctx->state.buffer.b[0]);
	for (i = 1; i < ctx->state.buffer.size; i++) {
		printf(" %02x", ctx->state.buffer.b[i]);
	}
	printf("\n\n");
}
#endif	/* PRINT_INTER */


/* print hex */
void print_hex(const char *msg, const unsigned char *data, int length)
{
	int i = 0;

	if (msg) {
		printf("%s: ", msg);
	}

	for (i = 0; i < length; i++) {
		if ((i % 32) == 0) {
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
}

/* print test-vector */
void print_test_vector_result(const unsigned char *key, int key_len,
		const unsigned char *iv, int iv_len,
		const unsigned char *keystream, int keystream_len)
{
	printf("\n");
	print_hex("Key        ", key, key_len);

	print_hex("IV         ", iv, iv_len);
	print_hex("Test Vector", keystream, 16);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
	int i;
	uint8_t key[ENOCORO128_KEY_BYTE_SIZE] = {0};
	uint8_t iv[ENOCORO_IV_BYTE_SIZE] = {0};

	FILE* file_in = fopen("in.bin", "rb");
	FILE* file_out = fopen("out.bin", "wb");

	if(file_in == NULL || file_out == NULL){
		printf("Erro ao abrir os arquivos!\n");
		return 1;
	}

	
	/* clear key-length and IV-size */
	uint32_t keysize = ENOCORO128_KEY_BYTE_SIZE;
	uint32_t ivsize = ENOCORO_IV_BYTE_SIZE;

	/* clear key-stream area */
	uint8_t keystream[TEST_VECTOR_BYTE_SIZE] = {0};

	/*buffers utilizados*/
	uint8_t buffer_arquivo[TEST_VECTOR_BYTE_SIZE];
	uint8_t buffer_keystream[TEST_VECTOR_BYTE_SIZE];
	size_t bytes_lidos;

	/* define context-struct */
	ENOCORO_Ctx ctx; 
	memset(&ctx, 0, sizeof (ctx));
	ENOCORO_init(&ctx, key, keysize, iv, ivsize);
	
	while((bytes_lidos = fread(buffer_arquivo, 1, TEST_VECTOR_BYTE_SIZE, file_in)) > 0){

		// Gera 'bytes_lidos' de bytes keystream
		ENOCORO_keystream(&ctx, buffer_keystream, bytes_lidos);

		// Faz o XOR manual entre os bytes lidos do arquivo e os gerados na keystream
		for(size_t i = 0; i < bytes_lidos; i++){
			buffer_arquivo[i] = buffer_arquivo[i] ^ buffer_keystream[i];
		}

		fwrite(buffer_arquivo, 1, bytes_lidos, file_out);
	}

	fclose(file_in);
	fclose(file_out);

	printf("Concluido!\n");
	return 0;
}