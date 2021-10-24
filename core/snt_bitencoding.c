#include "snt_bitencoding.h"

void snt_bit_encoding(enum SntBitEncoding encoding, const uint32_t *src, uint32_t *dst, unsigned int size) {

	switch (encoding) {
	case SntBitEncoding_Manchester:
		snt_bit_encoding_manchester(src, dst, size);
		break;
	case SntBitEncoding_10b_8b:
		break;
	default:
		break;
	}
}
void snt_bit_decoding(enum SntBitEncoding encoding, const uint32_t *src, uint32_t *dst, unsigned int size) {}

void snt_bit_encoding_manchester(const uint32_t *src, uint32_t *dst, unsigned int size) {
	const uint32_t nBits = sizeof(uint32_t) * 8;
	const uint32_t dataBitSize = size * 8;

	const uint32_t prev;

	/**/
	for (unsigned int i = 0; i < nBits; i++) {
		/*	*/
		const uint32_t bitIndex = i % dataBitSize;

		/*	Convert a bit index to array index and bit offset.	*/
		const uint32_t arrayIndex = bitIndex / nBits;
		const uint32_t bitFlipIndex = bitIndex % nBits;

		const uint32_t n = (src[arrayIndex] << bitFlipIndex) & 0x1;
		if (n == 0) {
			dst[arrayIndex] |= (1 << bitFlipIndex);
		} else if (n == 1) {
			dst[arrayIndex] |= (1 << bitFlipIndex);
		}
		// dst[i] =
	}
}
void snt_bit_decoding_manchester(const uint32_t *src, uint32_t *dst, unsigned int size) {}
