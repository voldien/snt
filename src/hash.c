#include"snt_hash.h"
#include<openssl/sha.h>
#include<openssl/md5.h>

const char* gc_hash_symbol[] = {
		"none",
		"md5",
		"sha",
		"sha224",
		"sha256",
		"sha384",
		"sha512",
		NULL
};


unsigned int sntHash(unsigned int hashtype, const void* block, unsigned int len,
		void* result) {

	union{
		MD5_CTX* md5;
		SHA_CTX* sha;
		SHA256_CTX* sha256;
		SHA512_CTX* sha512;
	}ctx;

	switch(hashtype){
	case SNT_HASH_MD5:
		ctx.md5 = (MD5_CTX*)malloc(sizeof(MD5_CTX));
		MD5_Init(ctx.md5);
		MD5_Update(ctx.md5, block, len);
		if(!MD5_Final(result, ctx.md5)){
			return 0;
		}
		break;
	case SNT_HASH_SHA:
		ctx.sha = malloc(sizeof(SHA_CTX));
		SHA1_Init(ctx.sha);
		SHA1_Update(ctx.sha, block, len);
		if(!SHA1_Final(result, ctx.sha)){
			return 0;
		}
		break;
	case SNT_HASH_SHA224:
		ctx.sha256 = malloc(sizeof(SHA256_CTX));
		SHA224_Init(ctx.sha256);
		SHA224_Update(ctx.sha256, block, len);
		if(!SHA224_Final(result, ctx.sha256)){
			return 0;
		}
		break;
	case SNT_HASH_SHA256:
		ctx.sha256 = malloc(sizeof(SHA256_CTX));
		SHA256_Init(ctx.sha256);
		SHA256_Update(ctx.sha256, block, len);
		if(!SHA256_Final(result, ctx.sha256)){
			return 0;
		}
		break;
	case SNT_HASH_SHA384:
		ctx.sha512 = malloc(sizeof(SHA512_CTX));
		SHA384_Init(ctx.sha512);
		SHA384_Update(ctx.sha512, block, len);
		if(!SHA384_Final(result, ctx.sha512)){
			return 0;
		}
		break;
	case SNT_HASH_SHA512:
		ctx.sha512 = malloc(sizeof(SHA512_CTX));
		SHA512_Init(ctx.sha512);
		SHA512_Update(ctx.sha512, block, len);
		if(!SHA512_Final(result, ctx.sha512)){
			return 0;
		}
		break;
	default:
		return 0;
	}

	free(ctx.md5);
	return sntGetHashTypeSize(hashtype);
}


unsigned int sntGetHashTypeSize(unsigned int hashtype){
	switch(hashtype){
	case SNT_HASH_MD5:
		return MD5_DIGEST_LENGTH;
	case SNT_HASH_SHA:
		return SHA_DIGEST_LENGTH;
	case SNT_HASH_SHA224:
		return SHA224_DIGEST_LENGTH;
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

