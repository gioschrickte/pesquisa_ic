/* ecrypt-sync.h */

/*
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 *
 * *** Please only edit parts marked with "[edit]". ***
 */

#ifndef ECRYPT_SYNC
#define ECRYPT_SYNC

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/*
 * The name of your cipher.
 */
#define ECRYPT_NAME "Rabbit Stream Cipher"

#define ECRYPT_MAXKEYSIZE 128
#define ECRYPT_KEYSIZE(i) (128 + (i)*32)

#define ECRYPT_MAXIVSIZE 64
#define ECRYPT_IVSIZE(i) (64 + (i)*64)

/* ------------------------------------------------------------------------- */

/* Data structures */

typedef struct
{
   u32 x[8];
   u32 c[8];
   u32 carry;
} RABBIT_ctx;

typedef struct
{
   RABBIT_ctx master_ctx;
   RABBIT_ctx work_ctx;
} ECRYPT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

void ECRYPT_init(void);

void ECRYPT_keysetup(
  ECRYPT_ctx* ctx,
  const u8* key,
  u32 keysize,                /* Key size in bits. */
  u32 ivsize);                /* IV size in bits. */

void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx,
  const u8* iv);

#define ECRYPT_HAS_SINGLE_BYTE_FUNCTION
#ifdef ECRYPT_HAS_SINGLE_BYTE_FUNCTION

#define ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext, msglen)   \
  ECRYPT_process_bytes(0, ctx, plaintext, ciphertext, msglen)

#define ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext, msglen)   \
  ECRYPT_process_bytes(1, ctx, ciphertext, plaintext, msglen)

void ECRYPT_process_bytes(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  ECRYPT_ctx* ctx,
  const u8* input,
  u8* output,
  u32 msglen);                /* Message length in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional features */

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx,
  u8* keystream,
  u32 length);

#endif

/* ------------------------------------------------------------------------- */

#define ECRYPT_BLOCKLENGTH 16

#endif
