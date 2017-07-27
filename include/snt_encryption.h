/**
    Simple network benchmark tool.
    Copyright (C) 2017  Valdemar Lindberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef _SNT_ENCRYPTION_H_
#define _SNT_ENCRYPTION_H_ 1
#include"snt_def.h"

typedef struct snt_connection_t SNTConnection;

/**
 *	Symmetric cipher.
 *	mutually exclusive enumerates.
 */
#define SNT_ENCRYPTION_NONE             0x0     /*	No symmetric encryption cipher.	*/
#define SNT_ENCRYPTION_AES_ECB128       0x1     /*	AES 128 bit key Electronic Codebook.	*/
#define SNT_ENCRYPTION_AES_ECB192       0x2     /*	AES 192 bit key Electronic Codebook.	*/
#define SNT_ENCRYPTION_AES_ECB256       0x4     /*	AES 256 bit key Electronic Codebook.	*/
#define SNT_ENCRYPTION_BLOWFISH         0x8     /*	BlowFish.	*/
#define SNT_ENCRYPTION_DES              0x10    /*	DES. (Data encryption standard), don't use unless you know what you're doing.*/
#define SNT_ENCRYPTION_3DES             0x20    /*	3DES.	*/
#define SNT_ENCRYPTION_AES_CBC128       0x40    /*	Cipher Block Chaining.	*/
#define SNT_ENCRYPTION_AES_CBC192       0x80    /*	Cipher Block Chaining.	*/
#define SNT_ENCRYPTION_AES_CBC256       0x100   /*	Cipher Block Chaining.	*/
#define SNT_ENCRYPTION_AES_CFB128       0x200   /*	Cipher Feedback.	*/
#define SNT_ENCRYPTION_AES_CFB192       0x400   /*	Cipher Feedback.	*/
#define SNT_ENCRYPTION_AES_CFB256       0x800   /*	Cipher Feedback.	*/
#define SNT_ENCRYPTION_AES_OFB128       0x1000  /*	Cipher Ouput feedback.	*/
#define SNT_ENCRYPTION_AES_OFB192       0x2000  /*	Cipher Ouput feedback.	*/
#define SNT_ENCRYPTION_AES_OFB256       0x4000  /*	Cipher Ouput feedback.	*/
#define SNT_ENCRYPTION_3DESCBC          0x8000  /*	3DES Cipher Block Chaining.	*/
#define SNT_ENCRYPTION_BF_CBC           0x10000 /*	Blowfish cipher block chaining.	*/
#define SNT_ENCRYPTION_BF_CFB           0x20000 /*	Blowfish cipher feedback.	*/
#define SNT_ENCRYPTION_RC4              0x40000 /*	RC4 encryption.	*/
#define SNT_ENCRYPTION_CAST             0x80000 /*	CAST.	*/
#define SNT_ENCRYPTION_CASTCBC          0x100000/*	CAST Cipher block chaining.	*/
#define SNT_ENCRYPTION_CASTCFB          0x200000/*	CAST Cipher feedback.	*/
#define SNT_ENCRYPTION_SYM_ALL									\
        ( SNT_ENCRYPTION_BLOWFISH                               \
        | SNT_ENCRYPTION_DES | SNT_ENCRYPTION_3DES              \
        | SNT_ENCRYPTION_AES_ECB128 | SNT_ENCRYPTION_AES_ECB192 \
        | SNT_ENCRYPTION_AES_ECB256 | SNT_ENCRYPTION_AES_CBC128 \
        | SNT_ENCRYPTION_AES_CBC192 | SNT_ENCRYPTION_AES_CBC256 \
        | SNT_ENCRYPTION_AES_CFB128 | SNT_ENCRYPTION_AES_CFB192 \
        | SNT_ENCRYPTION_AES_CFB256)

/**
 *	Symmetric cipher symbol table.
 */
extern const char* gc_symchi_symbol[];

/**
 *	Asymmetric cipher, aka public key cipher.
 */
#define SNT_ENCRYPTION_ASYM_NONE    0x0     /*	No Asymmetric cipher.	*/
#define SNT_ENCRYPTION_ASYM_RSA     0x1     /*	RSA.	*/
#define SNT_ENCRYPTION_ASYM_ALL         \
        ( SNT_ENCRYPTION_ASYM_RSA )     \

/**
 *  Asymmetric cipher symbol table.
 */
extern const char* gc_asymchi_symbol[];

/**
 *	Generate asymmetric key.
 *
 *	The data associated with the asymmetric
 *	key will be stored in the 'connection'.
 *
 *	@Return none zero if successfully.
 */
extern int sntASymGenerateKey(SNTConnection* connection,
		unsigned int cipher, unsigned int numbits);

/**
 *	Create asymmetric key from data block.
 *
 *	@Return none zero if successfully.
 */
extern int sntASymCreateKeyFromData(SNTConnection* __restrict__ connection,
		unsigned int cipher, const void* __restrict__ data, int len, unsigned int private);

/**
 *	Copy public key from asymmetric cipher to
 *	cpkey.
 *
 *	@Return non zero if successfully.
 */
extern int sntASymCopyPublicKey(
		const SNTConnection* __restrict__ connection, void* __restrict__ cpkey);

/**
 *	Load asymmetric key from file.
 *	Not supported.
 */
extern int sntASymCreateKeyFromFile(SNTConnection* __restrict__ connection,
		const char* __restrict__ cfilepath);

/**
 *	Encrypt data block with asymmetric cipher.
 *
 *	@Return number of bytes encrypted.
 */
extern int sntASymPubEncrypt(unsigned int type, const void* __restrict__ source,
		unsigned int len, void* __restrict__ dest,
		const void* __restrict__ key);

/**
 *	Decrypt data block with asymmetric cipher.
 *
 *	@Return number of bytes decrypted.
 */
extern int sntASymPriDecrypt(unsigned int type, const void* __restrict__ input,
		unsigned int len, void* __restrict__ output,
		const void* __restrict__ key);

/**
 *	Get block size of asymmetric cipher.
 *
 *	@Return size in bytes.
 */
extern unsigned int sntASymGetBlockSize(unsigned int cipher, const void* key);

/**
 *	Free all asymmetric encryption data
 *	associated with the connection. All associated asymmetric
 *	variable in the connection will be memset to zero.
 */
extern void sntASymFree(SNTConnection* connection);

/**
 *	Create signed digital signature.
 *
 *	@Return if successfully size of the signature in bytes. zero if failed.
 */
extern int sntASymSignDigSign(const SNTConnection* __restrict__ connection,
		unsigned int hashtype, const void* __restrict__ hash, unsigned int len,
		void* __restrict__ output, unsigned int* __restrict__ diglen);

/**
 *	Verify signed digital signature.
 *
 *	@Return if successfully size of the verified in bytes. zero if failed.
 */
extern int sntASymVerifyDigSign(const SNTConnection* __restrict__ connection,
		unsigned int hashtype, const void* __restrict__ hash, unsigned int len,
		void* __restrict__ digital, unsigned int diglen);

/**
 *	Generate symmetric key
 *	from random number.
 *
 *	@Return non zero if successfully.
 */
extern int sntSymGenerateKey(SNTConnection* connection, unsigned int cipher);

/**
 *	Create symmetric cipher key
 *	from specified key.
 *
 *	@Return non zero if successfully.
 */
extern int sntSymCreateFromKey(SNTConnection* __restrict__ connection,
		unsigned int cipher, const void* __restrict__ pkey);

/**
 *	Copy symmetric cipher.
 *
 *	Remark:
 */
extern void sntSymCopyKey(SNTConnection* __restrict__ connection,
		void** __restrict__ key);

/**
 *	Get key bit size of given symmetric
 *	cipher.
 */
extern int sntSymKeyBitSize(unsigned int cipher);

/**
 *	@Return key size in bytes.
 */
extern int sntSymKeyByteSize(unsigned int cipher);

/**
 *	@Return block size in bytes.
 */
extern int sntSymBlockSize(unsigned int cipher);

/**
 *	@Return none zero if cipher enumerator uses IV.
 */
extern unsigned int sntSymNeedIV(unsigned int cipher);

/**
 *	@Return none zero if cipher enumerator uses feedback.
 */
extern unsigned int sntSymdNeedFB(unsigned int cipher);

/**
 *	Free all associated symmetric cipher data that is
 *	associated with the connection.
 */
extern void sntSymFree(SNTConnection* connection);

/**
 *	Encrypt block.
 *
 *	Remark: The data will be encrypted with the symmetric
 *	cipher that the connection is assigned with.
 *
 *	The size returned will be a multiple of the block size.
 *
 *	@Return	number of bytes encrypted.
 */
extern unsigned int sntSymEncrypt(const SNTConnection* __restrict__ connection,
		const void* __restrict__ data, unsigned char* __restrict__ output,
		unsigned int len, void* __restrict__ iv, int* __restrict__ feedback);

/**
 *	Decrypt block.
 *
 *	Remark: The data will be decrypted with the symmetric
 *	cipher that the connection is assigned with.
 *
 *	The size returned will be a multiple of the block size.
 *
 *	@Return	number of bytes decrypted.
 */
extern unsigned int sntSymDecrypt(const SNTConnection* __restrict__ connection,
		const void* __restrict__ data, unsigned char* __restrict__ output,
		unsigned int len, void* __restrict__ iv, int* __restrict__ feedback);

/**
 *	Compute the total size of encryption data chunk.
 *	The size has to be a multiple of block size.
 */
extern unsigned int sntSymTotalBlockSize(unsigned int len, unsigned int blocksize);

/**
 *	Print error from openssl from previously invoked function
 *	from the openssl API.
 */
extern void sntSSLPrintError(void);

#endif
