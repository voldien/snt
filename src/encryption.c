#include "snt_encryption.h"
#include "snt_protocol.h"
#include "snt_log.h"
#include <stdarg.h>
#include <assert.h>
#include <sys/mman.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/evp.h>


const char* gc_symchi_symbol[] = {
		"",
		"aesecb128",
		"aesecb192",
		"aesecb256",
		"blowfish",
		"des",
		"3des",
		"aescbc128",
		"aescbc192",
		"aescbc256",
		"aesfbc128",
		"aesfbc192",
		"aesfbc256",
		NULL,
};

const char* gc_asymchi_symbol[] = {
		"",
		"RSA",
		"elliptic-curves",
		NULL,
};

static void sntSSLPrintError(void){
	char buf[256];
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), buf);
	fprintf(stderr, "Error encrypting message: %s\n", buf);
}

int sntASymGenerateKey(SNTConnection* connection, unsigned int cipher, unsigned int numbits){

	int e;					/*	*/
	int ret;				/*	*/
	size_t asymksize = 0;	/*	*/
	/*	RSA	*/
	const RSA_METHOD* method;	/*	*/
	BIGNUM* ebnum;				/*	*/

	/*	EC - Elliptic Curve.	*/
	EC_KEY* key = NULL;
	BIGNUM *prv = NULL;
	EC_POINT *pub = NULL;

	switch(cipher){
	case SNT_ENCRYPTION_ASYM_ECD:
		fprintf(stderr, "Not supported.\n");
		return 0;
		key = EC_KEY_new_by_curve_name(NID_secp224r1);
		if(key == NULL){
			return 0;
		}

		if( EC_KEY_generate_key(key) != 1){
			EC_KEY_free(key);
			return 0;
		}

		if( EC_KEY_set_private_key(key, prv) != 1){
			EC_KEY_free(key);
			return 0;
		}

		if(EC_KEY_set_public_key(key, pub) != 1){
			EC_KEY_free(key);
			return 0;
		}

		break;
	case SNT_ENCRYPTION_ASYM_RSA:

		/*	Create big number for RSA.	*/
		ebnum = BN_new();
		if(ebnum == NULL){
			sntSSLPrintError();
			return 0;
		}
		if(BN_set_word(ebnum, RSA_F4) != 1){
			sntSSLPrintError();
			BN_free(ebnum);
			sntASymFree(connection);
			return 0;
		}

		/*	Create new RSA.	*/
		connection->RSAkey = RSA_new();
		if(connection->RSAkey == NULL){
			sntSSLPrintError();
			BN_free(ebnum);
			sntASymFree(connection);
			return 0;
		}

		/*	Generate RSA keys.	*/
		ret = RSA_generate_key_ex(connection->RSAkey, numbits, ebnum, NULL);
		if( ret != 1){
			sntSSLPrintError();
			BN_free(ebnum);
			sntASymFree(connection);
			return 0;
		}

		/*	*/
		method = RSA_get_default_method();
		RSA_set_method(connection->RSAkey, method);
		BN_free(ebnum);

		/*	*/
		if(RSA_check_key(connection->RSAkey) <= 0){
			sntSSLPrintError();
			sntASymFree(connection);
			return 0;
		}

		asymksize = sizeof(RSA);

		break;
	default:
		fprintf(stderr, "Invalid asymmetric cipher.\n");
		return 0;
	}

	/*	Prevent sensitive information from being swapped to disk.	*/
	e = mlock(connection->asymkey, asymksize);
	if( e != 0){
		fprintf(stderr, "mlock failed, %s.\n", strerror(errno));
		sntASymFree(connection);
		return 0;
	}

	/*	*/
	connection->asymchiper = cipher;
	connection->asynumbits = numbits;

	return 1;
}

int sntASymCreateKeyFromData(SNTConnection* connection,
		unsigned int cipher, const void* key, int len) {

	int e;						/*	*/
	size_t asymksize = 0;		/*	*/
	int bitsize = 0;			/*	*/
	BIO* keybio = NULL;			/*	*/

	switch(cipher){
	case SNT_ENCRYPTION_ASYM_RSA:
		/*	Create buffer to write to.	*/
		keybio = BIO_new(BIO_s_mem());
		if(keybio == NULL){
			sntSSLPrintError();
			return 0;
		}

		/*	Write key to BIO.	*/
		if(BIO_write(keybio, key, len) <= 0){
			sntSSLPrintError();
			BIO_free_all(keybio);
			return 0;
		}

		/*	Create RSA public key.	*/
		connection->RSAkey = PEM_read_bio_RSAPublicKey(keybio, (RSA**)&connection->RSAkey, NULL, NULL);
		if(connection->RSAkey == NULL){
			sntSSLPrintError();
			sntASymFree(connection);
			BIO_free_all(keybio);
			return 0;
		}
		RSA_set_method(connection->RSAkey, RSA_get_default_method());
		asymksize = sizeof(RSA);
		bitsize = RSA_size(connection->RSAkey) * 8;

		break;
	case SNT_ENCRYPTION_ASYM_ECD:
		fprintf(stderr, "Not supported.\n");
		return 0;
	default:
		return 0;
	}

	/*	Assign assoicated information of asymmetric key.	*/
	connection->asymchiper = cipher;
	connection->asynumbits = (unsigned int)bitsize;
	sntDebugPrintf("Created asymmetric %s : %d bits.\n", gc_asymchi_symbol[sntLog2MutExlusive32(cipher)], bitsize);

	/*	*/
	BIO_free_all(keybio);

	/*	Prevent sensitive information from being swapped to disk.	*/
	e = mlock(connection->asymkey, asymksize);
	if( e != 0){
		fprintf(stderr, "mlock failed, %s.\n", strerror(e));
		sntASymFree(connection);
		return 0;
	}

	return 1;
}

int sntASymCopyPublicKey(const SNTConnection* connection, void* cpkey){

	int res;
	size_t pub_len;
	BIO* pub;

	switch(connection->asymchiper){
	case SNT_ENCRYPTION_ASYM_RSA:
		pub = BIO_new(BIO_s_mem());
		if(!pub){
			sntSSLPrintError();
			return 0;
		}
		res = PEM_write_bio_RSAPublicKey(pub, connection->RSAkey);
		if(res != 1){
			BIO_free_all(pub);
			sntSSLPrintError();
			return 0;
		}
		break;
	case SNT_ENCRYPTION_ASYM_ECD:
		break;
	default:
		return 0;
	}

	/*	Copy the key.	*/
	pub_len = BIO_pending(pub);
	BIO_read(pub, cpkey, pub_len);
	BIO_free_all(pub);

	return pub_len;
}

int sntASymPubEncrypt(unsigned int type, const void* source, unsigned int len,
		void* dest, const void* key) {

	int reslen = 0;

	switch(type){
	case SNT_ENCRYPTION_ASYM_RSA:
		reslen = RSA_public_encrypt(len, source, dest, (RSA*)key,
				RSA_PKCS1_PADDING);
		if(reslen < 0){
			sntSSLPrintError();
			return 0;
		}
		break;
	case SNT_ENCRYPTION_ASYM_ECD:
		break;
	case SNT_ENCRYPTION_ASYM_NONE:
	default:
		break;
	}

	return reslen;
}

int sntASymPriDecrypt(unsigned int cipher, const void* source, unsigned int len,
		void* dest, const void* key) {

	int reslen = 0;

	switch(cipher){
	case SNT_ENCRYPTION_ASYM_RSA:
		reslen = RSA_private_decrypt(len, (const unsigned char *)source,
				dest, (RSA*)key, RSA_PKCS1_PADDING);
		if(reslen < 0){
			sntSSLPrintError();
			return 0;
		}
		break;
	case SNT_ENCRYPTION_ASYM_ECD:
		break;
	case SNT_ENCRYPTION_ASYM_NONE:
	default:
		break;
	}

	return reslen;
}

unsigned int sntASymGetBlockSize(unsigned int cipher, const void* key){
	switch(cipher){
	case SNT_ENCRYPTION_ASYM_RSA:
		return RSA_size((RSA*)key);
		break;
	default:
		break;
	}
	return 0;
}

void sntASymFree(SNTConnection* connection){
	switch (connection->asymchiper) {
	case SNT_ENCRYPTION_ASYM_RSA:
		RSA_free(connection->RSAkey);
		break;
	case SNT_ENCRYPTION_ASYM_ECD:
		ECDSA_SIG_free(NULL);
		break;
	default:
		break;
	}

	/*	Update connection asymmetric cipher state.	*/
	connection->asymchiper = SNT_ENCRYPTION_ASYM_NONE;
	connection->asymkey = NULL;
	connection->asynumbits = 0;
}

static int sntGetSignHashEnum(unsigned int hash){
	switch(hash){
	case SNT_HASH_MD4:
		return NID_md4;
	case SNT_HASH_MD5:
		return NID_md5;
	case SNT_HASH_SHA:
		return NID_sha1;
	case SNT_HASH_SHA224:
		return NID_sha224;
	case SNT_HASH_SHA256:
		return NID_sha256;
	case SNT_HASH_SHA384:
		return NID_sha384;
	case SNT_HASH_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

int sntASymSignDigSign(const SNTConnection* connection, unsigned int hashtype,
		const void* hash, unsigned int len, void* output, unsigned int* diglen) {

	int res = 0;

	/*	Sign.	*/
	res = RSA_sign(sntGetSignHashEnum(hashtype), hash, len, output, diglen, connection->RSAkey);
	if(res != 1){
		sntSSLPrintError();
		return 0;
	}
	return res;
}
int sntASymVerifyDigSign(const SNTConnection* connection, unsigned int hashtype,
		const void* hash, unsigned int len, void* digital, unsigned int diglen) {

	int res = 0;

	/*	Verify.	*/
	res = RSA_verify(sntGetSignHashEnum(hashtype), hash, len, digital, diglen, connection->RSAkey);
	if(res != 1){
		sntSSLPrintError();
		return 0;
	}
	return res;
}


int sntSymGenerateKey(SNTConnection* connection, unsigned int cipher){

	int status;					/*	*/
	unsigned char* rand;		/*	*/

	/*	*/
	RAND_poll();

	/*	Generate random string.	*/
	rand = (unsigned char*)malloc(sntSymKeyByteSize(cipher));
	status = RAND_bytes(rand, sntSymKeyByteSize(cipher));
	if(status != 1){
		printf("error : %d\n", RAND_status());
		return 0;
	}
	/*	set seed.	*/
	RAND_seed((const void*)rand, status);

	status = sntSymCreateFromKey(connection, cipher, rand);
	sntMemZero(rand, sntSymKeyByteSize(cipher));
	free(rand);

	return status;
}

int sntSymCreateFromKey(SNTConnection* connection, unsigned int cipher, const void* pkey){

	int e;
	int symcipsize = 0;

	switch(cipher){
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		connection->aes = malloc(sizeof(AES_KEY));
		connection->deaes = malloc(sizeof(AES_KEY));
		AES_set_encrypt_key(pkey, sntSymKeyBitSize(cipher), connection->aes);
		AES_set_decrypt_key(pkey, sntSymKeyBitSize(cipher), connection->deaes);
		symcipsize = sizeof(AES_KEY);
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		connection->blowfish = malloc(sizeof(BF_KEY));
		BF_set_key(connection->blowfish, sntSymKeyByteSize(cipher), pkey);
		symcipsize = sizeof(BF_KEY);
		break;
	case SNT_ENCRYPTION_DES:
	case SNT_ENCRYPTION_3DES:
		printf("DES3 not supported.\n");
		connection->des3 = malloc(sizeof(DES_key_schedule));
		symcipsize = sizeof(DES_key_schedule);
		break;
	default:
		return 0;
	}

	/*	Prevent key to be swapped to storage.	*/
	e = mlock(connection->symmetrickey, symcipsize);
	if( e != 0){
		fprintf(stderr, "mlock failed, %s.\n", strerror(e));
		return 0;
	}

	/*	*/
	connection->symchiper = cipher;
	connection->blocksize = sntSymBlockSize(cipher);

	return 1;
}

void sntSymCopyKey(SNTConnection* connection, void** key){

	*key = calloc(1, sntSymKeyByteSize(connection->symchiper));
	assert(*key);

	switch(connection->symchiper){
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		memcpy(*key, ((AES_KEY*)connection->aes)->rd_key, sntSymKeyByteSize(connection->symchiper));
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		memcpy(*key, ((BF_KEY*)connection->blowfish)->P, sntSymKeyByteSize(connection->symchiper));
		break;
	case SNT_ENCRYPTION_3DES:
		break;
	case SNT_ENCRYPTION_DES:
		/*((DES_key_schedule*)connection->des3)->ks;*/
		break;
	default:
		break;
	}
}


int sntSymKeyBitSize(unsigned int cipher){
	switch(cipher){
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CFB128:
		return 128;
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CFB192:
		return 192;
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_CFB256:
		return 256;
	case SNT_ENCRYPTION_BLOWFISH:
		return 192;
	case SNT_ENCRYPTION_DES:
		return 56;
	default:
		return 0;
	}
}

int sntSymKeyByteSize(unsigned int cipher){
	return sntSymKeyBitSize(cipher) / 8;
}

int sntSymBlockSize(unsigned int cipher){
	switch(cipher){
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		return AES_BLOCK_SIZE;
	case SNT_ENCRYPTION_BLOWFISH:
		return BF_BLOCK;
	case SNT_ENCRYPTION_DES:
		return DES_KEY_SZ;
	default:
		return 0;
	}
}

void sntSymFree(SNTConnection* connection){

	switch(connection->symchiper){
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		free(connection->aes);
		free(connection->deaes);
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		free(connection->blowfish);
		break;
	case SNT_ENCRYPTION_3DES:
		free(connection->des3);
		break;
	case SNT_ENCRYPTION_DES:
		break;
	case SNT_ENCRYPTION_NONE:
	default:
		break;
	}

	/*	Update connection symmetric cipher state.	*/
	connection->symchiper = SNT_ENCRYPTION_NONE;
	connection->symmetrickey = NULL;
	connection->desymmetrickey = NULL;
	connection->blocksize = 0;
}

static unsigned char tmpiv[16] = {2,3,3,2,3,2,1};	/*	TODO resolved later, Used for testing */
int dummy = 6;

unsigned int sntSymEncrypt(const SNTConnection* connection, const void* source,
		unsigned char* dest, unsigned int soulen) {

	unsigned int i;
	unsigned int delen = soulen;
	const unsigned char* in = source;

	/*	Compute the total block size.	*/
	delen = sntSymTotalBlockSize(soulen, connection->blocksize);

	/*	Zero out padding.	*/
	memset(dest + soulen, 0, (delen - soulen));

	/*	Encryption.	*/
	switch(connection->symchiper){
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
		for(i = 0; i < delen; i += connection->blocksize){
			AES_ecb_encrypt(in + i, dest + i, connection->aes, AES_ENCRYPT);
		}
		break;
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
		AES_cbc_encrypt(in, dest, delen, connection->aes, tmpiv, AES_ENCRYPT);
		break;
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		break;
	case SNT_ENCRYPTION_DES:

		break;
	case SNT_ENCRYPTION_3DES:
		for(i = 0; i < delen; i += connection->blocksize){
			DES_encrypt1((unsigned int*)(source + i), connection->des3, 0);
		}
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		for(i = 0; i < delen; i += connection->blocksize){
			BF_ecb_encrypt((source + i), (dest + i), connection->blowfish, BF_ENCRYPT);
		}
		break;
	default:
		memcpy(dest, source, delen);
		break;
	}

	return delen;
}

unsigned int sntSymDecrypt(const SNTConnection* connection, const void* source,
		unsigned char* dest, unsigned int soulen) {

	unsigned int deslen;
	const unsigned char* in = source;
	unsigned int i;

	/*	Compute the total block size.	*/
	deslen = sntSymTotalBlockSize(soulen, connection->blocksize);

	/*	Decryption.	*/
	switch(connection->symchiper){
	case SNT_ENCRYPTION_AES_ECB128:
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_ECB256:
		for(i = 0; i < deslen; i += connection->blocksize){
			AES_ecb_encrypt(in + i, dest + i, connection->deaes, DES_DECRYPT);
		}
		break;
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
		AES_cbc_encrypt(source, dest, deslen, connection->deaes, tmpiv, AES_DECRYPT);/**/
		break;
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		AES_cfb128_encrypt(in, dest, deslen, connection->deaes, tmpiv, &dummy, AES_DECRYPT);
		break;
	case SNT_ENCRYPTION_DES:
		for(i = 0; i < deslen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i),(DES_LONG*)(in + i), connection->blocksize);
			DES_encrypt1((DES_LONG*)(dest + i), connection->symmetrickey, DES_DECRYPT);
		}
		break;
	case SNT_ENCRYPTION_3DES:
		for(i = 0; i < deslen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i),(DES_LONG*)(in + i), connection->blocksize);
			DES_decrypt3((DES_LONG*)(dest + i),
					&((DES_key_schedule*)connection->des3)[0],
					&((DES_key_schedule*)connection->des3)[1],
					&((DES_key_schedule*)connection->des3)[2]);
		}
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		for(i = 0; i < deslen; i += connection->blocksize){
			BF_ecb_encrypt((in + i), (dest + i), connection->blowfish, BF_DECRYPT);
		}
		break;
	default:
		memcpy(dest, source, deslen);
		break;
	}

	/*	*/
	return deslen;
}

unsigned int sntSymTotalBlockSize(unsigned int len, unsigned int blocksize){
	if(len % blocksize == 0)
		return len;
	else
		return len + (blocksize - (len % blocksize));
}
