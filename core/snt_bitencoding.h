#ifndef _SNT_BIT_ENCONDING_H_
#define _SNT_BIT_ENCONDING_H_ 1
#include "snt_def.h"

#ifdef __cplusplus /*	C++ Environment	*/
extern "C" {
#endif

enum SntBitEncoding {
	SntBitEncoding_Manchester,
	SntBitEncoding_10b_8b,
	SntBitEncoding_NRZ,
};

extern SNTDECLSPEC void snt_bit_encoding(enum SntBitEncoding encoding, const uint32_t *src, uint32_t *dst,
										 unsigned int size);
extern SNTDECLSPEC void snt_bit_decoding(enum SntBitEncoding encoding, const uint32_t *src, uint32_t *dst,
										 unsigned int size);


extern SNTDECLSPEC void snt_bit_encoding_manchester(const uint32_t *src, uint32_t *dst, unsigned int size);
extern SNTDECLSPEC void snt_bit_decoding_manchester(const uint32_t *src, uint32_t *dst, unsigned int size);

#ifdef __cplusplus /*	C++ Environment	*/
}
#endif

#endif
