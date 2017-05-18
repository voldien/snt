#include"snt_hash.h"
#include<openssl/sha.h>
#include<openssl/md5.h>

const char* gc_hash_symbol[] = {
		"None",
		"md5",
		"sha",
		"sha256",
		"sha384",
		"sha512",
		NULL
};


int sntHash(unsigned int hashtype, const void* block, unsigned int len,
		void* res) {

	union{
		MD5_CTX* md5;
		SHA_CTX* sha;
		SHA256_CTX* sha256;
		SHA512_CTX* sha512;
	}hash;

	switch(hashtype){
	case SNT_HASH_MD5:
		hash.md5 = (MD5_CTX*)malloc(sizeof(MD5_CTX));
		MD5_Init(hash.md5);
		MD5_Update(hash.md5, block, len);
		if(!MD5_Final(res, hash.md5)){
			return 0;
		}
		break;
	case SNT_HASH_SHA:
		hash.sha = malloc(sizeof(SHA_CTX));
		SHA1_Init(hash.sha);
		SHA1_Update(hash.sha, block, len);
		if(!SHA1_Final(res, hash.sha)){
			return 0;
		}
		break;
	case SNT_HASH_SHA256:
		hash.sha256 = malloc(sizeof(SHA256_CTX));
		SHA256_Init(hash.sha256);
		SHA256_Update(hash.sha256, block, len);
		if(!SHA256_Final(res, hash.sha256)){
			return 0;
		}
		break;
	case SNT_HASH_SHA384:
		hash.sha512 = malloc(sizeof(SHA512_CTX));
		SHA384_Init(hash.sha512);
		SHA384_Update(hash.sha512, block, len);
		if(!SHA384_Final(res, hash.sha512)){
			return 0;
		}
		break;
	case SNT_HASH_SHA512:
		hash.sha512 = malloc(sizeof(SHA512_CTX));
		SHA512_Init(hash.sha512);
		SHA512_Update(hash.sha512, block, len);
		if(!SHA512_Final(res, hash.sha512)){
			return 0;
		}
		break;
	default:
		return 0;
	}

	free(hash.md5);
	return sntGetHashTypeSize(hashtype);
}


unsigned int sntGetHashTypeSize(unsigned int hashtype){
	switch(hashtype){
	case SNT_HASH_MD5:
		return MD5_DIGEST_LENGTH;
	case SNT_HASH_SHA:
		return SHA_DIGEST_LENGTH;
	case SNT_HASH_SHA256:
		return SHA256_DIGEST_LENGTH;
	case SNT_HASH_SHA384:
		return SHA384_DIGEST_LENGTH;
	case SNT_HASH_SHA512:
		return SHA512_DIGEST_LENGTH;
	default:
		return 0;
	}
}

