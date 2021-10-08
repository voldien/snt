#ifndef _SNT_CRC_H_
#define _SNT_CRC_H_ 1

#ifdef __cplusplus /*	C++ Environment	*/
extern "C" {
#endif

enum SntCRCAlgorithm {
	CRC7,
	CRC8,
	CRC10,
	CRC11,
	CRC15,
	CRC24,
	CRC30,
	CRC32,
	CRC64,
	XOR8,
	XOR16,
	XOR32,
};

#ifdef __cplusplus /*	C++ Environment	*/
}
#endif

#endif