#ifndef _TB_CRC32_H_
#define _TB_CRC32_H_

#include "tb_defs.h"

typedef tb_uint32 tb_crc32_t;

#ifdef __cplusplus
extern "C" {
#endif

void TB_API tb_crc32_init(tb_crc32_t *ctx);

void TB_API tb_crc32_update(tb_crc32_t *ctx, 
	const void *buf, tb_uint32 buf_len);

tb_uint32 TB_API tb_crc32_final(tb_crc32_t *ctx);

tb_uint32 TB_API tb_crc32(const void *buf, tb_uint32 buf_len);

#ifdef __cplusplus
}
#endif

#endif //_TB_CRC32_H_
