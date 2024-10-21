#ifndef _TB_AES_H_
#define _TB_AES_H_

#include <stddef.h>
#include "tb_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TB_AES_BLOCK_SIZE 16	// AES operates on 16 bytes at a time

//AES
// Key setup must be done before any AES en/de-cryption functions can be used.
tb_int32 TB_API tb_aes_key_setup(
	const tb_byte *key,	// The key, must be 128, 192, or 256 bits
	tb_uint32 *w,		// Output key schedule to be used later
	tb_int32 keysize);	// Bit length of the key, 128, 192, or 256

void TB_API tb_aes_encrypt(
	const tb_byte *in,		// 16 bytes of plaintext
	tb_byte *out,			// 16 bytes of ciphertext
	const tb_uint32 *key,	// From the key setup
	tb_int32 keysize);		// Bit length of the key, 128, 192, or 256

void TB_API tb_aes_decrypt(
	const tb_byte *in,		// 16 bytes of ciphertext
	tb_byte *out,			// 16 bytes of plaintext
	const tb_uint32 *key,	// From the key setup
	tb_int32 keysize);		// Bit length of the key, 128, 192, or 256

//////////////////////////////////////////////////////////////////////////
//AES - CBC
tb_int32 TB_API tb_aes_encrypt_cbc(
	const tb_byte *in,	// Plaintext
	size_t in_len,		// Must be a multiple of TB_AES_BLOCK_SIZE
	tb_byte *out,		// Ciphertext, same length as plaintext
	const tb_uint32 *key,// From the key setup
	tb_int32 keysize,	// Bit length of the key, 128, 192, or 256
	const tb_byte *iv);	// IV, must be TB_AES_BLOCK_SIZE bytes long

tb_int32 TB_API tb_aes_decrypt_cbc(const tb_byte *in, size_t in_len, 
	tb_byte *out, const tb_uint32 *key, tb_int32 keysize, const tb_byte *iv);

// Only output the CBC-MAC of the input.
tb_int32 TB_API tb_aes_encrypt_cbc_mac(
	const tb_byte *in,	// plaintext
	size_t in_len,		// Must be a multiple of TB_AES_BLOCK_SIZE
	tb_byte *out,		// Output MAC
	const tb_uint32 *key,// From the key setup
	tb_int32 keysize,	// Bit length of the key, 128, 192, or 256
	const tb_byte *iv);	// IV, must be TB_AES_BLOCK_SIZE bytes long

//////////////////////////////////////////////////////////////////////////
// AES - CTR
void TB_API tb_aes_increment_iv(
	tb_byte *iv,			// Must be a multiple of TB_AES_BLOCK_SIZE
	tb_int32 counter_size);	// Bytes of the IV used for counting (low end)

void TB_API tb_aes_encrypt_ctr(
	const tb_byte *in,		// Plaintext
	size_t in_len,			// Any tb_byte length
	tb_byte *out,			// Ciphertext, same length as plaintext
	const tb_uint32 *key,	// From the key setup
	tb_int32 keysize,		// Bit length of the key, 128, 192, or 256
	const tb_byte *iv);		// IV, must be TB_AES_BLOCK_SIZE bytes long

void TB_API tb_aes_decrypt_ctr(
	const tb_byte *in,		// Ciphertext
	size_t in_len,			// Any tb_byte length
	tb_byte *out,			// Plaintext, same length as ciphertext
	const tb_uint32 *key,	// From the key setup
	tb_int32 keysize,		// Bit length of the key, 128, 192, or 256
	const tb_byte *iv);		// IV, must be TB_AES_BLOCK_SIZE bytes long

//////////////////////////////////////////////////////////////////////////
// AES - CCM
// Returns 0 if the input parameters do not violate any constraint.
tb_int32 TB_API tb_aes_encrypt_ccm(
	const tb_byte *plaintext,		// IN  - Plaintext.
	tb_uint32 plaintext_len,		// IN  - Plaintext length.
	const tb_byte *associated_data,	// IN  - Associated Data included in authentication, but not encryption.
	tb_uint16 associated_data_len,	// IN  - Associated Data length in bytes.
	const tb_byte *nonce,			// IN  - The Nonce to be used for encryption.
	tb_uint16 nonce_len,			// IN  - Nonce length in bytes.
	tb_byte *ciphertext,			// OUT - Ciphertext, a concatination of the plaintext and the MAC.
	tb_uint32 *ciphertext_len,		// OUT - The length of the ciphertext, always plaintext_len + mac_len.
	tb_uint32 mac_len,				// IN  - The desired length of the MAC, must be 4, 6, 8, 10, 12, 14, or 16.
	const tb_byte *key,				// IN  - The AES key for encryption.
	tb_int32 keysize);				// IN  - The length of the key in bits. Valid values are 128, 192, 256.

// Returns 0 if the input parameters do not violate any constraint.
// Use mac_auth to ensure decryption/validation was preformed correctly.
// If authentication does not succeed, the plaintext is zeroed out. To overwride
// this, call with mac_auth = NULL. The proper proceedure is to decrypt with
// authentication enabled (mac_auth != NULL) and make a second call to that
// ignores authentication explicitly if the first call failes.
tb_int32 TB_API tb_aes_decrypt_ccm(
	const tb_byte *ciphertext,	// IN  - Ciphertext, the concatination of encrypted plaintext and MAC.
	tb_uint32 ciphertext_len,	// IN  - Ciphertext length in bytes.
	const tb_byte *assoc,		// IN  - The Associated Data, required for authentication.
	tb_uint16 assoc_len,		// IN  - Associated Data length in bytes.
	const tb_byte *nonce,		// IN  - The Nonce to use for decryption, same one as for encryption.
	tb_uint16 nonce_len,		// IN  - Nonce length in bytes.
	tb_byte *plaintext,			// OUT - The plaintext that was decrypted. Will need to be large enough to hold ciphertext_len - mac_len.
	tb_uint32 *plaintext_len,	// OUT - Length in bytes of the output plaintext, always ciphertext_len - mac_len .
	tb_uint32 mac_len,			// IN  - The length of the MAC that was calculated.
	tb_int32 *mac_auth,			// OUT - TRUE if authentication succeeded, FALSE if it did not. NULL pointer will ignore the authentication.
	const tb_byte *key,			// IN  - The AES key for decryption.
	tb_int32 keysize);			// IN  - The length of the key in BITS. Valid values are 128, 192, 256.

#ifdef __cplusplus
}
#endif

#endif //_TB_AES_H_
