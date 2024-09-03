#ifndef _TB_SHA256_H_
#define _TB_SHA256_H_

#include "tb_defs.h"

#define TB_SHA256_SIZE 32            // SHA256 outputs a 32 tb_byte digest

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	tb_byte data[64];
	tb_uint32 datalen;
	tb_uint32 bits[2]; //bitlen
	tb_uint32 state[8];
} tb_sha256_t;

void TB_API tb_sha256_init(tb_sha256_t *ctx);

void TB_API tb_sha256_update(tb_sha256_t *ctx, 
	const void *data, tb_uint32 len);

void TB_API tb_sha256_final(tb_sha256_t *ctx, tb_byte *hash);

void TB_API tb_sha256(const void* data, tb_uint32 len, tb_byte* hash);

#ifdef __cplusplus
}
#endif

#endif //_TB_SHA256_H_