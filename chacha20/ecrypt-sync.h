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
#define ECRYPT_NAME "ChaCha20"
#define ECRYPT_PROFILE "_____"

/*
 * Specify which key and IV sizes are supported by your cipher.
 * All sizes are in bits.
 */

#define ECRYPT_MAXKEYSIZE 256                 /* [edit] */
#define ECRYPT_KEYSIZE(i) (128 + (i)*128)     /* [edit] */

#define ECRYPT_MAXIVSIZE 64                   /* [edit] */
#define ECRYPT_IVSIZE(i) (64 + (i)*64)        /* [edit] */

/* ------------------------------------------------------------------------- */

/*
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher.
 */

typedef struct
{
  u32 input[16]; /* could be compressed */
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

void ECRYPT_encrypt_bytes(
  ECRYPT_ctx* ctx,
  const u8* plaintext,
  u8* ciphertext,
  u32 msglen);                /* Message length in bytes. */

void ECRYPT_decrypt_bytes(
  ECRYPT_ctx* ctx,
  const u8* ciphertext,
  u8* plaintext,
  u32 msglen);                /* Message length in bytes. */

/* ------------------------------------------------------------------------- */

/* Optional features */

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

#define ECRYPT_BLOCKLENGTH 64                  /* [edit] */

#define ECRYPT_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#define ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#ifdef ECRYPT_GENERATES_KEYSTREAM

#define ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
  ECRYPT_keystream_bytes(ctx, keystream,                           \
    (blocks) * ECRYPT_BLOCKLENGTH)

#endif

#endif

/* ------------------------------------------------------------------------- */

#endif
