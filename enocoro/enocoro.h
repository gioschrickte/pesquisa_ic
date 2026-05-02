/****************************************************/
/* Systems Development Lab., Hitachi, Ltd.          */
/* Rev.1.0                                          */
/* 2 February 2010                                  */
/* (c) Hitachi, Ltd. 2010. All rights reserved.     */
/****************************************************/
/**
 * @file
 * @brief enocoro-128 include_file
 *
 */
#ifndef _ENOCORO_H_
#define _ENOCORO_H_


#ifndef __GNUC__
# ifndef __uint32_t_defined
	typedef unsigned char   uint8_t;
	typedef unsigned short  uint16_t;
	typedef unsigned int    uint32_t;
# define __uint32_t_defined
# endif /* __uint32_t_defined */
#else
# include <stdint.h>
#endif /* __GNUC__ */

/** key-length */
#define ENOCORO128_KEYSIZE          128
#define ENOCORO128_KEY_BYTE_SIZE    16
	
/** max key-length */
#define ENOCORO_MAXKEYSIZE          ENOCORO128_KEYSIZE
#define ENOCORO_MAXKEY_BYTE_SIZE    ENOCORO128_KEY_BYTE_SIZE

/** IV-size */
#define ENOCORO_IVSIZE              64
#define ENOCORO_IV_BYTE_SIZE        8

/** max IV-size */
#define ENOCORO_MAXIVSIZE           ENOCORO_IVSIZE
#define ENOCORO_MAXIV_BYTE_SIZE     ENOCORO_IV_BYTE_SIZE

/* enocoro-128 paramter */
/** buffer-size(bytes) */
#define ENOCORO128_BUFFER_BYTE_SIZE     32
	
/** state-size(bytes) */
#define ENOCORO_STATE_BYTE_SIZE         2

/** max buffer-size(bytes) */
#define ENOCORO_MAX_BUFFER_BYTE_SIZE    ENOCORO128_BUFFER_BYTE_SIZE

/** round-number for init */
#define INIT_ROUND_NUM_128 96


/**
 * buffer-struct
 */
typedef struct enocoro_buffer{
	uint8_t         top;		/** buffer top */
	uint8_t         size;		/** buffer-size */
	uint8_t         b[ENOCORO_MAX_BUFFER_BYTE_SIZE];	/** buffer-area */
} ENOCORO_Buffer;


/**
 * state-struct
 */
typedef struct enocoro_state {
	uint8_t         iv[ENOCORO_IV_BYTE_SIZE];	/** IV-area */
	uint8_t         a[ENOCORO_STATE_BYTE_SIZE];	/** state-area */
	ENOCORO_Buffer  buffer;				/** buffer-area */
} ENOCORO_State;


/**
 * context-struct
 */
typedef struct enocoro_context {
	uint8_t         key[ENOCORO_MAXKEY_BYTE_SIZE];	/** key-area */
	uint32_t        keysize;			/** key-length */
	uint32_t        ivsize;				/** IV-size */
	ENOCORO_State   state;				/** state-area */
} ENOCORO_Ctx;


/**
 * setup init
 *
 * @param ctx       context-struct
 * @param key       key
 * @param keysize   key-length
 * @param iv        IV
 * @param ivsize    IV-size
 */
void ENOCORO_init(ENOCORO_Ctx *ctx, const uint8_t *key, uint32_t keysize,
		const uint8_t *iv, uint32_t ivsize);


/**
 * create rondum value
 *
 * @param ctx        context-struct
 * @param keystream  key-stream area
 * @param length     key-stream length
 */
void ENOCORO_keystream(ENOCORO_Ctx *ctx, uint8_t *keystream, uint32_t length);


#endif /* _ENOCORO_H_ */
