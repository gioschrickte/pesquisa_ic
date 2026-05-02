/* trivium.h
 *
 * Header derivado da implementação de referência do Trivium em C++,
 * obtida do repositório crocs-muni/CryptoStreams (que envelopa em
 * namespace C++ a referência original de Christophe De Cannière,
 * K.U.Leuven, submetida ao eSTREAM). O conteúdo algorítmico é
 * preservado integralmente; apenas o envelope C++ (namespaces e
 * classes) foi removido para uso direto em C.
 *
 * Renomeação:
 *   ECRYPT_keysetup       -> TRIVIUM_keysetup
 *   ECRYPT_ivsetup        -> TRIVIUM_ivsetup
 *   ECRYPT_encrypt_bytes  -> TRIVIUM_encrypt_bytes
 *   ECRYPT_decrypt_bytes  -> TRIVIUM_decrypt_bytes
 *
 * Justificativa: evitar conflito de símbolos caso múltiplas cifras
 * eSTREAM sejam linkadas no mesmo binário. A semântica é idêntica.
 */

#ifndef TRIVIUM_H
#define TRIVIUM_H

#include "ecrypt-portable.h"

#define TRIVIUM_NAME "TRIVIUM"

#define TRIVIUM_KEYSIZE_BITS 80
#define TRIVIUM_IVSIZE_BITS  80

/* Número de rodadas de inicialização da especificação oficial.
 * O CRoCS parametriza para análise round-reduced; aqui fixamos no
 * valor canônico (9 iterações × 2 = 18 chamadas UPDATE/ROTATE,
 * correspondendo aos 1152 passos de clock da spec do De Cannière). */
#define TRIVIUM_INIT_ROUNDS 9

typedef struct {
    u64 init[2];
    u64 state[6];
} TRIVIUM_ctx;

void TRIVIUM_keysetup(TRIVIUM_ctx *ctx, const u8 *key, u32 keysize, u32 ivsize);
void TRIVIUM_ivsetup (TRIVIUM_ctx *ctx, const u8 *iv);
void TRIVIUM_encrypt_bytes(TRIVIUM_ctx *ctx, const u8 *plaintext, u8 *ciphertext, u32 msglen);
void TRIVIUM_decrypt_bytes(TRIVIUM_ctx *ctx, const u8 *ciphertext, u8 *plaintext, u32 msglen);

#endif
