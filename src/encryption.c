#include "snt_encryption.h"
#include "snt_protocol.h"
#include "snt_log.h"
#include "snt_schd.h"
#include "snt_rand.h"
#include <stdarg.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/rc4.h>
#include <openssl/cast.h>
#include <openssl/err.h>
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
		"aescfb128",
		"aescfb192",
		"aescfb256",
		"aesofb128",
		"aesofb192",
		"aesofb256",
		"3descbc",
		"bfcbc",
		"bfcfb",
		"rc4",
		"cast",
		"castcbc",
		"castcfb",
		NULL,
};

const char* gc_asymchi_symbol[] = {
		"",
		"RSA",
		NULL,
};

void sntSSLPrintError(void){
	char buf[256];
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), buf);
	sntLogErrorPrintf("Error encrypting message: %s\n", buf);
}

int sntASymGenerateKey(SNTConnection* connection, unsigned int cipher, unsigned int numbits){

	int ret;					/*	*/
	size_t asymksize = 0;		/*	*/
	/*	RSA	*/
	const RSA_METHOD* method;	/*	*/
	BIGNUM* ebnum;				/*	*/

	/*	*/
	int codes;
	BN_GENCB* bn;

	switch(cipher){
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
		connection->asymkey = RSA_new();
		if(connection->asymkey == NULL){
			sntSSLPrintError();
			BN_free(ebnum);
			sntASymFree(connection);
			return 0;
		}

		/*	Generate RSA keys.	*/
		ret = RSA_generate_key_ex(connection->asymkey, numbits, ebnum, NULL);
		if( ret != 1){
			sntSSLPrintError();
			BN_free(ebnum);
			sntASymFree(connection);
			return 0;
		}

		/*	*/
		method = RSA_get_default_method();
		RSA_set_method(connection->asymkey, method);
		BN_free(ebnum);

		/*	Check RSA key.	*/
		if(RSA_check_key(connection->asymkey) <= 0){
			sntSSLPrintError();
			sntASymFree(connection);
			return 0;
		}

		asymksize = RSA_size((RSA*)connection->asymkey);
		// asymksize = sizeof(RSA);

		break;
	default:
		sntLogErrorPrintf("Invalid asymmetric cipher.\n");
		return 0;
	}

	/*	Prevent sensitive information from being swapped to disk.	*/
	if(!sntLockMemory(connection->asymkey, asymksize)){
		sntASymFree(connection);
		return 0;
	}

	/*	*/
	connection->asymchiper = cipher;
	connection->asynumbits = numbits;

	return 1;
}

int sntASymCreateKeyFromData(SNTConnection* __restrict__ connection,
		unsigned int cipher, const void* __restrict__ key, int len, unsigned int private) {

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
		if(private){
			connection->asymkey = PEM_read_bio_RSAPrivateKey(keybio, (RSA**)&connection->asymkey, NULL, NULL);
		}
		else{
			connection->asymkey = PEM_read_bio_RSAPublicKey(keybio, (RSA**)&connection->asymkey, NULL, NULL);
		}
		if(connection->asymkey == NULL){
			sntSSLPrintError();
			sntASymFree(connection);
			BIO_free_all(keybio);
			return 0;
		}
		RSA_set_method(connection->asymkey, RSA_get_default_method());
		asymksize = RSA_size(connection->asymkey) * 8;
		bitsize = RSA_size(connection->asymkey) * 8;

		break;
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
	if(!sntLockMemory(connection->asymkey, asymksize)){
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
		res = PEM_write_bio_RSAPublicKey(pub, connection->asymkey);
		if(res != 1){
			BIO_free_all(pub);
			sntSSLPrintError();
			return 0;
		}
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

int sntASymCreateKeyFromFile(const SNTConnection* __restrict__ connection,
		unsigned int cipher, void* __restrict__ filepath, unsigned int private) {

	int res;
	long int len;
	void* pkey;

	/*	Load content of the file.	*/
	len = sntLoadFile(filepath, &pkey);
	if(len <= 0){
		return 0;
	}

	/*	Create key from data.	*/
	res = sntASymCreateKeyFromData(connection, cipher, pkey, len, private);

	/*	Release key.	*/
	sntMemZero(pkey, len);
	free(pkey);

	return res;
}

int sntASymCreateFromX509File(SNTConnection* __restrict__ connection,
		const char* __restrict__ cfilepath){

	STACK_OF(X509_INFO) *certstack;
	BIO* bio;
	int i;
	EVP_PKEY *pkey;
	X509_INFO *stack_item = NULL;
	X509_NAME *certsubject = NULL;
	X509* cert;
	unsigned int asym = 0;

	/*	Load file.	*/
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, cfilepath) <= 0) {
		sntSSLPrintError();
		return 0;
	}

	/*	Read x509 from PEM file.	*/
	if (!(cert = PEM_read_bio_X509(bio, NULL, 0, NULL))) {
		sntSSLPrintError();
		return 0;
	}

	/*	Extract public key from x509.	*/
	if ((pkey = X509_get_pubkey(cert)) == NULL) {
		sntSSLPrintError();
		return 0;
	}

	/*	Check public key type.	*/
	
	switch (EVP_MD_type(pkey)) {
	case EVP_PKEY_RSA:
		asym = SNT_ENCRYPTION_ASYM_RSA;
		connection->asymkey = EVP_PKEY_get1_RSA(pkey);
		break;
    case EVP_PKEY_DSA:
    case EVP_PKEY_EC:
	default:
		sntLogErrorPrintf("Not Supported.\n");
		return 0;
	}

	/*	Assign asymmetric meta. */
	connection->asymchiper = asym;
    connection->asynumbits = (unsigned int)EVP_PKEY_size(pkey) * 8;

	/*	Release.    */
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free_all(bio);

	return 1;
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
	case SNT_ENCRYPTION_ASYM_NONE:
	default:
		break;
	}

	return reslen;
}

unsigned int sntASymGetBlockSize(unsigned int cipher, const void* key){

	assert(key);

	switch(cipher){
	case SNT_ENCRYPTION_ASYM_RSA:
		return (unsigned int)RSA_size((RSA*)key);
	default:
		break;
	}
	return 0;
}

void sntASymFree(SNTConnection* connection){
	switch (connection->asymchiper) {
	case SNT_ENCRYPTION_ASYM_RSA:
		RSA_free(connection->asymkey);
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

	switch(connection->asymchiper){
	case SNT_ENCRYPTION_ASYM_RSA:
		/*	Sign.	*/
		res = RSA_sign(sntGetSignHashEnum(hashtype), hash, len, output, diglen, connection->asymkey);
		if(res != 1){
			sntSSLPrintError();
			return 0;
		}
		break;
	default:
		sntLogErrorPrintf("not supported.\n");
		break;
	}
	return res;
}
int sntASymVerifyDigSign(const SNTConnection* connection, unsigned int hashtype,
		const void* hash, unsigned int len, void* digital, unsigned int diglen) {

	int res = 0;

	switch(connection->asymchiper){
	case SNT_ENCRYPTION_ASYM_RSA:
		/*	Verify.	*/
		res = RSA_verify(sntGetSignHashEnum(hashtype), hash, len, digital, diglen, connection->asymkey);
		if(res != 1){
			sntSSLPrintError();
			return 0;
		}
		break;
	default:
		sntLogErrorPrintf("not supported.\n");
		break;
	}
	return res;
}

int sntSymGenerateKey(SNTConnection* connection, unsigned int cipher){

	int status;					/*	*/
	unsigned char* rand;		/*	*/

	/*	Generate random key.	*/
	rand = (unsigned char*)malloc(sntSymKeyByteSize(cipher));
	sntGenRandom(rand, sntSymKeyByteSize(cipher));

	/*	Create symmetric key.	*/
	status = sntSymCreateFromKey(connection, cipher, rand);

	/*	Clear key.	*/
	sntMemZero(rand, sntSymKeyByteSize(cipher));
	free(rand);

	return status;
}

int sntSymCreateFromKey(SNTConnection* connection, unsigned int cipher, const void* pkey){

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
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
		connection->symenc = malloc(sizeof(AES_KEY));
		connection->symdec = malloc(sizeof(AES_KEY));
		AES_set_encrypt_key(pkey, sntSymKeyBitSize(cipher), connection->symenc);
		AES_set_decrypt_key(pkey, sntSymKeyBitSize(cipher), connection->symdec);
		symcipsize = sizeof(AES_KEY);
		break;
	case SNT_ENCRYPTION_BLOWFISH:
	case SNT_ENCRYPTION_BF_CBC:
	case SNT_ENCRYPTION_BF_CFB:
		connection->symenc = malloc(sizeof(BF_KEY));
		BF_set_key(connection->symenc, sntSymKeyByteSize(cipher), pkey);
		symcipsize = sizeof(BF_KEY);
		break;
	case SNT_ENCRYPTION_DES:
		connection->symenc = malloc(sizeof(DES_key_schedule));
		symcipsize = sizeof(DES_key_schedule);
		/*if(DES_set_key_checked((const_DES_cblock*)&pkey, connection->des3) != 0){
			sntSSLPrintError();
			return 0;
		}*/
		if(DES_set_key((const_DES_cblock*)pkey, (DES_key_schedule *)connection->symenc) != 0){
			free(connection->symenc);
			sntSSLPrintError();
			return 0;
		}
		break;
	case SNT_ENCRYPTION_3DES:
	case SNT_ENCRYPTION_3DESCBC:
		connection->symenc = malloc(sizeof(DES_key_schedule) * 3);
		symcipsize = sizeof(DES_key_schedule) * 3;
		if(DES_set_key(&((const_DES_cblock*)pkey)[0], &((DES_key_schedule*)connection->symenc)[0]) != 0){
			sntSSLPrintError();
			return 0;
		}
		if(DES_set_key(&((const_DES_cblock*)pkey)[1], &((DES_key_schedule*)connection->symenc)[1]) != 0){
			sntSSLPrintError();
			return 0;
		}
		if(DES_set_key(&((const_DES_cblock*)pkey)[2], &((DES_key_schedule*)connection->symenc)[2]) != 0){
			sntSSLPrintError();
			return 0;
		}
		break;
	case SNT_ENCRYPTION_RC4:
		connection->symenc = malloc(sizeof(RC4_KEY));
		RC4_set_key(connection->symenc, sntSymKeyBitSize(cipher), pkey);
		break;
	case SNT_ENCRYPTION_CAST:
	case SNT_ENCRYPTION_CASTCBC:
	case SNT_ENCRYPTION_CASTCFB:
		connection->symenc = malloc(sizeof(CAST_KEY));
		symcipsize = sizeof(CAST_KEY);
		CAST_set_key((CAST_KEY*)connection->symenc, CAST_KEY_LENGTH, pkey);
		break;
	default:
		return 0;
	}

	/*	Prevent key to be swapped to storage.	*/
	if(!sntLockMemory(connection->symenc, symcipsize)){
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
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
		memcpy(*key, ((AES_KEY*)connection->symenc)->rd_key, sntSymKeyByteSize(connection->symchiper));
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		memcpy(*key, &((BF_KEY*)connection->symenc)->P[0], sntSymKeyByteSize(connection->symchiper));
		break;
	case SNT_ENCRYPTION_3DES:
	case SNT_ENCRYPTION_3DESCBC:
		memcpy(*key, &((DES_key_schedule*)connection->symenc)->ks[0].cblock, sntSymKeyByteSize(connection->symchiper));
		break;
	case SNT_ENCRYPTION_DES:
		memcpy(*key, &((DES_key_schedule*)connection->symenc)->ks[0].cblock, sntSymKeyByteSize(connection->symchiper));
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
	case SNT_ENCRYPTION_AES_OFB128:
		return 128;
	case SNT_ENCRYPTION_AES_ECB192:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_OFB192:
		return 192;
	case SNT_ENCRYPTION_AES_ECB256:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_CFB256:
	case SNT_ENCRYPTION_AES_OFB256:
		return 256;
	case SNT_ENCRYPTION_BLOWFISH:
	case SNT_ENCRYPTION_BF_CBC:
	case SNT_ENCRYPTION_BF_CFB:
		return 192;
	case SNT_ENCRYPTION_DES:
		return 56;
	case SNT_ENCRYPTION_3DES:
	case SNT_ENCRYPTION_3DESCBC:
		return sntSymKeyBitSize(SNT_ENCRYPTION_DES) * 3;
	case SNT_ENCRYPTION_RC4:
		return 128;
	case SNT_ENCRYPTION_CAST:
	case SNT_ENCRYPTION_CASTCBC:
	case SNT_ENCRYPTION_CASTCFB:
		return CAST_KEY_LENGTH;
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
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
		return AES_BLOCK_SIZE;
	case SNT_ENCRYPTION_BLOWFISH:
	case SNT_ENCRYPTION_BF_CBC:
	case SNT_ENCRYPTION_BF_CFB:
		return BF_BLOCK;
	case SNT_ENCRYPTION_DES:
	case SNT_ENCRYPTION_3DES:
	case SNT_ENCRYPTION_3DESCBC:
		return sizeof(DES_cblock);
	case SNT_ENCRYPTION_RC4:
		return 1;
	case SNT_ENCRYPTION_CAST:
	case SNT_ENCRYPTION_CASTCBC:
	case SNT_ENCRYPTION_CASTCFB:
		return CAST_BLOCK;
	default:
		return 0;
	}
}

unsigned int sntSymNeedIV(unsigned int cipher){
	switch(cipher){
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
	case SNT_ENCRYPTION_3DESCBC:
	case SNT_ENCRYPTION_CASTCBC:
	case SNT_ENCRYPTION_CASTCFB:
	case SNT_ENCRYPTION_BF_CBC:
	case SNT_ENCRYPTION_BF_CFB:
		return 1;
	default:
		return 0;
	}

}

unsigned int sntSymdNeedFB(unsigned int cipher){
	switch(cipher){
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
	case SNT_ENCRYPTION_CASTCFB:
	case SNT_ENCRYPTION_BF_CFB:
		return 1;
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
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:
		free(connection->symenc);
		free(connection->symdec);
		break;
	case SNT_ENCRYPTION_BLOWFISH:
	case SNT_ENCRYPTION_BF_CBC:
	case SNT_ENCRYPTION_BF_CFB:
		free(connection->symenc);
		break;
	case SNT_ENCRYPTION_3DES:
	case SNT_ENCRYPTION_DES:
	case SNT_ENCRYPTION_3DESCBC:
		free(connection->symenc);
		break;
	case SNT_ENCRYPTION_RC4:
		free(connection->symenc);
		break;
	case SNT_ENCRYPTION_CAST:
	case SNT_ENCRYPTION_CASTCBC:
	case SNT_ENCRYPTION_CASTCFB:
		free(connection->symenc);
		break;
	case SNT_ENCRYPTION_NONE:
	default:
		break;
	}

	/*	Update connection symmetric cipher state.	*/
	connection->symchiper = SNT_ENCRYPTION_NONE;
	connection->symenc = NULL;
	connection->symdec = NULL;
	connection->blocksize = 0;
}

unsigned int sntSymEncrypt(const SNTConnection* connection, const void* source,
		unsigned char* dest, unsigned int soulen, void* __restrict__ iv, int* __restrict__ feedback) {

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
			AES_ecb_encrypt(in + i, dest + i, connection->symenc, AES_ENCRYPT);
		}
		break;
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:{
		unsigned char iiv[16];
		sntGenRandom(iiv, sntSymBlockSize(connection->symchiper));
		memcpy(iv, iiv, sntSymBlockSize(connection->symchiper));
		AES_cbc_encrypt(in, dest, delen, connection->symenc, iiv, AES_ENCRYPT);
	}break;
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:{
		unsigned char iiv[16];
		sntGenRandom(iiv, sntSymBlockSize(connection->symchiper));
		memcpy(iv, iiv, sntSymBlockSize(connection->symchiper));
		*feedback = 0;
		AES_cfb128_encrypt(in, dest, delen, connection->symenc, iiv, feedback, AES_ENCRYPT);
	}break;
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:{
		unsigned char iiv[16];
		sntGenRandom(iiv, sntSymBlockSize(connection->symchiper));
		memcpy(iv, iiv, sntSymBlockSize(connection->symchiper));
		*feedback = 0;
		AES_ofb128_encrypt(in, dest, delen, connection->symenc, iiv, feedback);
	}break;
	case SNT_ENCRYPTION_DES:
		for(i = 0; i < delen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i), (DES_LONG*)(in + i), connection->blocksize);
			DES_encrypt1((unsigned int*)(dest + i), connection->symenc, DES_ENCRYPT);
		}
		break;
	case SNT_ENCRYPTION_3DES:
		for(i = 0; i < delen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i), (DES_LONG*)(in + i), connection->blocksize);
			DES_encrypt3((DES_LONG*)(dest + i), 					&((DES_key_schedule*)connection->symenc)[0],
					&((DES_key_schedule*)connection->symenc)[1],
					&((DES_key_schedule*)connection->symenc)[2]);
		}
		break;
	case SNT_ENCRYPTION_3DESCBC:{
		unsigned char iiv[8];
		sntGenRandom(iv, sntSymBlockSize(connection->symchiper));
		memcpy(iiv, iv, 8);
		DES_ede3_cbc_encrypt(in, dest, delen,
				&((DES_key_schedule*)connection->symenc)[0],
				&((DES_key_schedule*)connection->symenc)[1],
				&((DES_key_schedule*)connection->symenc)[2], iiv, DES_ENCRYPT);
	}break;
	case SNT_ENCRYPTION_BLOWFISH:
		for(i = 0; i < delen; i += connection->blocksize){
			BF_ecb_encrypt((in + i), (dest + i), connection->symenc, BF_ENCRYPT);
		}
		break;
	case SNT_ENCRYPTION_BF_CBC:{
		unsigned char iiv[8];
		sntGenRandom(iv, sntSymBlockSize(connection->symchiper));
		memcpy(iiv, iv, sntSymBlockSize(connection->symchiper));
		BF_cbc_encrypt(in, dest, delen, connection->symenc, iiv, BF_ENCRYPT);
	}break;
	case SNT_ENCRYPTION_BF_CFB:{
		unsigned char iiv[8];
		sntGenRandom(iv, sntSymBlockSize(connection->symchiper));
		memcpy(iiv, iv, 8);
		*feedback = 0;
		BF_cfb64_encrypt(in, dest, delen, connection->symenc, iiv, feedback, BF_ENCRYPT);
	}break;
	case SNT_ENCRYPTION_RC4:
		RC4(connection->symenc, delen, in, dest);
		break;
	case SNT_ENCRYPTION_CAST:
		for(i = 0; i < delen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i), (DES_LONG*)(in + i), connection->blocksize);
			CAST_encrypt((unsigned int*)(dest + i), connection->symenc);
		}
		break;
	case SNT_ENCRYPTION_CASTCBC:{
		unsigned char iiv[CAST_BLOCK];
		sntGenRandom(iv, sntSymBlockSize(connection->symchiper));
		memcpy(iiv, iv, CAST_BLOCK);
		CAST_cbc_encrypt(in, dest, delen, connection->symenc, iiv, CAST_ENCRYPT);
		break;
	case SNT_ENCRYPTION_CASTCFB:{
		unsigned char iiv[CAST_BLOCK];
		sntGenRandom(iv, sntSymBlockSize(connection->symchiper));
		memcpy(iiv, iv, CAST_BLOCK);
		*feedback = 0;
		CAST_cfb64_encrypt(in, dest, delen, connection->symenc, iv, feedback, CAST_ENCRYPT);
	}break;
	}default:
		memcpy(dest, source, delen);
		break;
	}

	/*	*/
	return delen;
}

unsigned int sntSymDecrypt(const SNTConnection* connection, const void* source,
		unsigned char* dest, unsigned int soulen, void* __restrict__ iv,
		int* __restrict__ feedback) {

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
			AES_ecb_encrypt(in + i, dest + i, connection->symdec, DES_DECRYPT);
		}
		break;
	case SNT_ENCRYPTION_AES_CBC128:
	case SNT_ENCRYPTION_AES_CBC192:
	case SNT_ENCRYPTION_AES_CBC256:
		AES_cbc_encrypt(in, dest, deslen, connection->symdec, iv, AES_DECRYPT);
		break;
	case SNT_ENCRYPTION_AES_CFB128:
	case SNT_ENCRYPTION_AES_CFB192:
	case SNT_ENCRYPTION_AES_CFB256:
		AES_cfb128_encrypt(in, dest, deslen, connection->symenc, iv, feedback, AES_DECRYPT);
		break;
	case SNT_ENCRYPTION_AES_OFB128:
	case SNT_ENCRYPTION_AES_OFB192:
	case SNT_ENCRYPTION_AES_OFB256:{
		AES_ofb128_encrypt(in, dest, deslen, connection->symenc, iv, feedback);
	}break;
	case SNT_ENCRYPTION_DES:
		for(i = 0; i < deslen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i),(DES_LONG*)(in + i), connection->blocksize);
			DES_encrypt1((DES_LONG*)(dest + i), connection->symenc, DES_DECRYPT);
		}
		break;
	case SNT_ENCRYPTION_3DES:
		for(i = 0; i < deslen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i),(DES_LONG*)(in + i), connection->blocksize);
			DES_decrypt3((DES_LONG*)(dest + i),
					&((DES_key_schedule*)connection->symenc)[0],
					&((DES_key_schedule*)connection->symenc)[1],
					&((DES_key_schedule*)connection->symenc)[2]);
		}
		break;
	case SNT_ENCRYPTION_3DESCBC:
			DES_ede3_cbc_encrypt(in, dest, deslen,
					&((DES_key_schedule*)connection->symenc)[0],
					&((DES_key_schedule*)connection->symenc)[1],
					&((DES_key_schedule*)connection->symenc)[2], iv, DES_DECRYPT);
		break;
	case SNT_ENCRYPTION_BLOWFISH:
		for(i = 0; i < deslen; i += connection->blocksize){
			BF_ecb_encrypt((in + i), (dest + i), connection->symenc, BF_DECRYPT);
		}
		break;
	case SNT_ENCRYPTION_BF_CBC:
		BF_cbc_encrypt(in, dest, deslen, connection->symenc, iv, BF_DECRYPT);
		break;
	case SNT_ENCRYPTION_BF_CFB:{
		BF_cfb64_encrypt(in, dest, deslen, connection->symenc, iv, feedback, BF_DECRYPT);
	}break;
	case SNT_ENCRYPTION_RC4:
		RC4(connection->symenc, deslen, in, dest);
		break;
	case SNT_ENCRYPTION_CAST:
		for(i = 0; i < deslen; i += connection->blocksize){
			memcpy((DES_LONG*)(dest + i), (DES_LONG*)(in + i), connection->blocksize);
			CAST_decrypt((unsigned int*)(dest + i), connection->symenc);
		}
		break;
	case SNT_ENCRYPTION_CASTCBC:
		CAST_cbc_encrypt(in, dest, deslen, connection->symenc, iv, CAST_DECRYPT);
		break;
	case SNT_ENCRYPTION_CASTCFB:
		CAST_cfb64_encrypt(in, dest, deslen, connection->symenc, iv, feedback, CAST_DECRYPT);
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
