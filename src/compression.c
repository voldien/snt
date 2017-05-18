#include"snt.h"
#include"snt_log.h"
#include"snt_compression.h"
#include<assert.h>
#include<lz4.h>
#include<zlib.h>

static const unsigned int compressbound = 2000;

const char* gs_symcompression[] = {
		"",
		"lz4",
		"gzip",
		NULL
};

void sntInitCompression(unsigned int type){

	if(type & SNT_COMPRESSION_LZ4){
		int err;
		sntDebugPrintf("Initialize LZ4, %d.\n", compressbound);
		err = LZ4_compressBound((int)LZ4_COMPRESSBOUND(compressbound));
		if(err <= 0){
			fprintf(stderr, "lz4 failed to initialize with error %d.\n", err);
			exit(EXIT_FAILURE);
		}
	}
	if(type & SNT_COMPRESSION_GZIP){
		uLong err;
		sntDebugPrintf("Initialize gzip, %d.\n", compressbound);
		err = compressBound((uLong)compressbound);
		if(err < compressbound){
			fprintf(stderr, "gzip failed to initialize with error %ld.\n", err);
			exit(EXIT_FAILURE);
		}
	}
}

int sntInflate(unsigned int com, const char* source, char* dest,
		unsigned int slen) {

	long int inflen = 0;
	int err;

	switch(com){
	case SNT_COMPRESSION_LZ4:
		inflen = LZ4_decompress_safe(source, dest, slen, compressbound);
		sntDebugPrintf("sntInflate, lz4 %u:%d.\n", slen, inflen);
		assert(inflen >= 0);
		break;
	case SNT_COMPRESSION_GZIP:
		err = uncompress((Bytef*)dest, (uLongf*)&inflen, (const Bytef*)source, (uLongf)slen);
		printf("%d.\n", err);
		assert(err == Z_OK);
		sntDebugPrintf("sntInflate, gzip %u:%d.\n", slen, inflen);
		assert(inflen >= 0);
		break;
	default:
		return (int)slen;
	}

	return (int)inflen;
}

int sntDeflate(unsigned int com, const char* source, char* dest,
		unsigned int slen) {

	long int deflen = 0;
	int err;

	switch(com){
	case SNT_COMPRESSION_LZ4:
		deflen = LZ4_compress(source, dest, slen);
		sntDebugPrintf("sntDeflate, lz4 %u:%d.\n", slen, deflen);
		assert(deflen >= 0);
		break;
	case SNT_COMPRESSION_GZIP:
		//err = compressBound((uLong)compressbound);
		err = compress((Bytef*)dest, (uLongf*) &deflen,
				(const Bytef*)source, (uLongf) slen);
		printf("%d.\n", err);
		assert(err == Z_OK);
		sntDebugPrintf("sntDeflate, gzip %u:%d.\n", slen, deflen);
		assert(deflen >= 0);
		break;
	default:
		return (int)slen;
	}

	return (int)deflen;
}

