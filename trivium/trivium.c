/* trivium.c
 *
 * Reference implementation of the TRIVIUM stream cipher
 * Author: Christophe De Cannière, K.U.Leuven.
 *
 * Esta versão foi obtida do repositório crocs-muni/CryptoStreams,
 * que mantém a implementação de referência envelopada em namespace
 * C++ para uso em seu framework. O conteúdo algorítmico (macros
 * UPDATE/ROTATE/LOAD/STORE, função TRIVIUM_process_bytes,
 * keysetup e ivsetup) é preservado byte-a-byte. A desenvelopagem
 * consistiu em:
 *   - remover os namespaces "stream_ciphers::estream"
 *   - substituir a classe ECRYPT_Trivium por funções livres
 *     operando sobre uma struct TRIVIUM_ctx passada por ponteiro
 *   - substituir throw std::runtime_error por assert()
 *   - fixar o número de rodadas de init em 9 (valor canônico da spec)
 *   - renomear ECRYPT_* -> TRIVIUM_* para evitar conflito de símbolos
 *
 * O algoritmo permanece intacto: mesma ordem de operações, mesmos
 * tipos numéricos, mesmas constantes, mesmo estado interno.
 */

#include <assert.h>
#include "trivium.h"
#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

#ifndef TRIVIUM_BIG_ENDIAN

/* Least significant bit first */
#define U64TO64_CONVERT U64TO64_LITTLE
#define M64TO64_CONVERT M64TO64_LITTLE
#define SF SR
#define SB SL

#define LOAD_IVLEN(len)  (U32V(len))
#define STORE_IVLEN(len) (U64V(len))

#define PADDING (U64C(0x0000000000000007) << (128 - 111))

#else

/* Most significant bit first */
#define U64TO64_CONVERT U64TO64_BIG
#define M64TO64_CONVERT M64TO64_BIG
#define SF SL
#define SB SR

#define LOAD_IVLEN(len)  (U32V(len >> 32))
#define STORE_IVLEN(len) (U64V(len) << 32)

#define PADDING (U64C(0xE000000000000000) >> (128 - 111))

#endif

/* ------------------------------------------------------------------------- */
/* Operadores de 64 bits.
 * Em ARM (sem __MMX__ e sem _M_IX86), cai sempre no caminho escalar. */

#if defined(ECRYPT_NATIVE64) || (!defined(__MMX__) && !defined(_M_IX86))

typedef u64 m64;

#define SL(m, i) ((m) << (i))
#define SR(m, i) ((m) >> (i))

#define OR(a, b)  ((a) | (b))
#define AND(a, b) ((a) & (b))
#define XOR(a, b) ((a) ^ (b))

#define M8V(m) U8V(m)

#define M64TO64_LITTLE(m) (m = U64TO64_LITTLE(m))
#define M64TO64_BIG(m)    (m = U64TO64_BIG(m))

#define EMPTY()

#else

#include <mmintrin.h>

typedef __m64 m64;

#define SL(m, i) _m_psllqi(m, i)
#define SR(m, i) _m_psrlqi(m, i)

#define OR(a, b)  _m_por(a, b)
#define AND(a, b) _m_pand(a, b)
#define XOR(a, b) _m_pxor(a, b)

#define M8V(m) U8V(_m_to_int(m))

#define M64TO64_LITTLE(m)
#define M64TO64_BIG(m) do {                                          \
    m = _m_por(_m_psllwi(m, 8),  _m_psrlwi(m, 8));                   \
    m = _m_por(_m_pslldi(m, 16), _m_psrldi(m, 16));                  \
    m = _m_por(_m_psllqi(m, 32), _m_psrlqi(m, 32));                  \
} while (0)

#define EMPTY() _m_empty()

#endif

/* ------------------------------------------------------------------------- */
/* Macros do algoritmo TRIVIUM */

#define S11(i) SB(s11, ((i) -  64))
#define S12(i) SF(s12, (128 - (i)))
#define S21(i) SB(s21, ((i) - 157))
#define S22(i) SF(s22, (221 - (i)))
#define S31(i) SB(s31, ((i) - 241))
#define S32(i) SF(s32, (305 - (i)))

#define S1(i) OR(S11(i), S12(i))
#define S2(i) OR(S21(i), S22(i))
#define S3(i) OR(S31(i), S32(i))

#define UPDATE() do {                                                \
    t1 = XOR(AND(S3(286), S3(287)), S1(69));                         \
    t2 = XOR(AND(S1(91),  S1(92)),  S2(171));                        \
    t3 = XOR(AND(S2(175), S2(176)), S3(264));                        \
                                                                     \
    s12 = XOR(S1(66),  S1(93));                                      \
    s22 = XOR(S2(162), S2(177));                                     \
    s32 = XOR(S3(243), S3(288));                                     \
                                                                     \
    t1 = XOR(t1, s32);                                               \
    t2 = XOR(t2, s12);                                               \
    t3 = XOR(t3, s22);                                               \
} while (0)

#define ROTATE() do {                                                \
    s12 = s11; s11 = t1;                                             \
    s22 = s21; s21 = t2;                                             \
    s32 = s31; s31 = t3;                                             \
} while (0)

#define LOAD(s) do {                                                 \
    s11 = ((m64*)(s))[1];                                            \
    s12 = ((m64*)(s))[0];                                            \
    s21 = ((m64*)(s))[3];                                            \
    s22 = ((m64*)(s))[2];                                            \
    s31 = ((m64*)(s))[5];                                            \
    s32 = ((m64*)(s))[4];                                            \
} while (0)

#define STORE(s) do {                                                \
    ((m64*)(s))[1] = s11;                                            \
    ((m64*)(s))[0] = s12;                                            \
    ((m64*)(s))[3] = s21;                                            \
    ((m64*)(s))[2] = s22;                                            \
    ((m64*)(s))[5] = s31;                                            \
    ((m64*)(s))[4] = s32;                                            \
} while (0)

/* ------------------------------------------------------------------------- */

void TRIVIUM_keysetup(TRIVIUM_ctx *ctx, const u8 *key, u32 keysize, u32 ivsize)
{
    /* Validações da implementação original (eram throw em C++).
     * Trivium aceita apenas key=80 bits; iv pode ser 32, 64 ou 80 bits. */
    assert(keysize == 80);
    assert(ivsize == 32 || ivsize == 64 || ivsize == 80);

    const u32 keylen = (keysize + 7) / 8;
    u32 i;
    u8 *s = (u8*)ctx->init + 16 - keylen;

    ctx->init[0] = ctx->init[1] = 0;

    for (i = 0; i < keylen; ++i, ++s)
        *s = key[i];

    ctx->init[0] = U64TO64_CONVERT(ctx->init[0]);
    ctx->init[1] = U64TO64_CONVERT(ctx->init[1]);

    ctx->init[0] |= STORE_IVLEN((ivsize + 7) / 8);
}

/* ------------------------------------------------------------------------- */

void TRIVIUM_ivsetup(TRIVIUM_ctx *ctx, const u8 *iv)
{
    const u32 ivlen = LOAD_IVLEN(ctx->init[0]);
    u32 i;
    u8 *s = (u8*)(ctx->state + 2) + 16 - ivlen;

    m64 s11, s12;
    m64 s21, s22;
    m64 s31, s32;

    ctx->state[0] = ctx->init[0];
    ctx->state[1] = ctx->init[1];

    ctx->state[4] = PADDING;
    ctx->state[5] = 0;

    ctx->state[2] = ctx->state[3] = 0;

    for (i = 0; i < ivlen; ++i, ++s)
        *s = iv[i];

    ctx->state[2] = U64TO64_CONVERT(ctx->state[2]);
    ctx->state[3] = U64TO64_CONVERT(ctx->state[3]);

    LOAD(ctx->state);

    /* Spec oficial: 9 iterações duplas = 1152 passos de clock */
    for (i = 0; i < TRIVIUM_INIT_ROUNDS; ++i) {
        m64 t1, t2, t3;
        UPDATE(); ROTATE();
        UPDATE(); ROTATE();
    }

    STORE(ctx->state);
    EMPTY();
}

/* ------------------------------------------------------------------------- */

static void TRIVIUM_process_bytes(int action, TRIVIUM_ctx *ctx,
                                  const u8 *input, u8 *output, u32 msglen)
{
    (void)action;  /* Trivium é simétrico (XOR): encrypt == decrypt */

    m64 s11, s12;
    m64 s21, s22;
    m64 s31, s32;

    LOAD(ctx->state);

    for (; (int)(msglen -= 16) >= 0; output += 16, input += 16) {
        m64 t1, t2, t3, z[2];

        UPDATE();
        z[0] = XOR(XOR(s12, s22), s32);
        ROTATE();
        UPDATE();
        z[1] = XOR(XOR(s12, s22), s32);
        ROTATE();

        M64TO64_CONVERT(z[0]);
        ((m64*)output)[0] = XOR(((m64*)input)[0], z[0]);
        M64TO64_CONVERT(z[1]);
        ((m64*)output)[1] = XOR(((m64*)input)[1], z[1]);
    }

    for (msglen += 16; (int)msglen > 0; msglen -= 8, output += 8, input += 8) {
        m64 t1, t2, t3, z;

        UPDATE();
        z = XOR(XOR(s12, s22), s32);

        if (msglen >= 8) {
            M64TO64_CONVERT(z);
            ((m64*)output)[0] = XOR(((m64*)input)[0], z);
        } else {
            u32 i;
            for (i = 0; i < msglen; ++i, z = SF(z, 8))
                output[i] = input[i] ^ M8V(z);
        }

        ROTATE();
    }

    STORE(ctx->state);
    EMPTY();
}

void TRIVIUM_encrypt_bytes(TRIVIUM_ctx *ctx, const u8 *plaintext, u8 *ciphertext, u32 msglen)
{
    TRIVIUM_process_bytes(0, ctx, plaintext, ciphertext, msglen);
}

void TRIVIUM_decrypt_bytes(TRIVIUM_ctx *ctx, const u8 *ciphertext, u8 *plaintext, u32 msglen)
{
    TRIVIUM_process_bytes(1, ctx, ciphertext, plaintext, msglen);
}
