#ifndef _TB_MD5_H_
#define _TB_MD5_H_

#include "tb_defs.h"

#define TB_MD5_SIZE 16   // MD5 outputs a 16 tb_byte digest

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	tb_uint32 state[4];
	tb_uint32 count[2];
	tb_uint8 buffer[64];
} tb_md5_t;

void TB_API tb_md5_init(tb_md5_t *md5);

// tb_md5_update是MD5的主计算过程，buf是要变换的字节串，len是长度,
// 调用之前需要调用MD5_Init
void TB_API tb_md5_update(tb_md5_t *md5, const void *buf, tb_uint32 buf_len);

/*--------------------------------------------------------------------------
 * 函数名：tb_md5_final
 * 功能：MD5计算结束，取最终结果
 * 参数1：digest是MD5计算结果
 * 参数2：md5是MD5计算中间变量
 * 返回：空
 *--------------------------------------------------------------------------*/
void TB_API tb_md5_final(tb_md5_t *md5, tb_uint8 digest[16]);

// buf是明文 buf_len是明文的长度
void TB_API tb_md5(const void *buf, tb_uint32 buf_len, tb_uint8 out[16]);

#ifdef __cplusplus
}
#endif

#endif //_TB_MD5_H_
