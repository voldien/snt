#include"snt.h"
#include"snt_log.h"
#include"snt_compression.h"
#include<assert.h>
#include<lz4.h>
#include<zlib.h>
#include<bzlib.h>

static unsigned int g_compressbound = 4096;

const char* gs_symcompression[] = {
		"",
		"lz4",
		"gzip",
		"bzip2",
		"lzma",
		"xz",
		NULL
};

bz_stream* bzip2com = NULL;
bz_stream* bzip2uncom = NULL;

void sntInitCompression(unsigned int type){

	if(type & SNT_COMPRESSION_LZ4){
		int err;
		int compbound = (int)LZ4_COMPRESSBOUND(g_compressbound);
		sntDebugPrintf("Initialize LZ4, %d.\n", compbound);
		g_compressbound = (unsigned int)compbound;
		err = LZ4_compressBound(compbound);
		if(err <= 0){
			fprintf(stderr, "lz4 failed to initialize with error %d.\n", err);
			exit(EXIT_FAILURE);
		}
	}
	if(type & SNT_COMPRESSION_GZIP){
		uLong err;
		err = compressBound((uLong)g_compressbound);
		g_compressbound = (unsigned int)err;
		sntDebugPrintf("Initialize gzip, %d.\n", g_compressbound);
		if(err < g_compressbound){
			fprintf(stderr, "gzip failed to initialize with error %ld.\n", err);
			exit(EXIT_FAILURE);
		}
	}
	if(type & SNT_COMPRESSION_BZIP2){
		int err;

		/*	Allocate.	*/
		bzip2com = malloc(sizeof(bz_stream));
		bzip2uncom = malloc(sizeof(bz_stream));
		memset(bzip2com, 0, sizeof(bz_stream));
		memset(bzip2uncom, 0, sizeof(bz_stream));

		/*	*/
		err = BZ2_bzCompressInit(bzip2com, 9, 0, 0);
		if(err < BZ_OK){
			fprintf(stderr, "bzip2 failed to initialize with error %ld.\n", err);
			exit(EXIT_FAILURE);
		}
		err = BZ2_bzDecompressInit(bzip2uncom, 0, 0);
		if(err < BZ_OK){
			fprintf(stderr, "bzip2 failed to initialize with error %ld.\n", err);
			exit(EXIT_FAILURE);
		}
	}

}

int sntInflate(unsigned int com, const char* source, char* dest,
		unsigned int slen) {

	long int inflen = 0;
	int i;
	int err;

	switch(com){
	case SNT_COMPRESSION_LZ4:
		inflen = LZ4_decompress_safe(source, dest, slen, g_compressbound);
		sntDebugPrintf("sntInflate, lz4 %u:%d.\n", slen, inflen);
		assert(inflen >= 0);
		break;
	case SNT_COMPRESSION_GZIP:
		inflen = g_compressbound;
		err = uncompress((Bytef*)dest, (uLongf*)&inflen, (const Bytef*)source, (uLongf)slen);
		assert(err == Z_OK);
		sntDebugPrintf("sntInflate, gzip %u:%d.\n", slen, inflen);
		assert(inflen >= 0);
		break;
	case SNT_COMPRESSION_BZIP2:
		bzip2uncom->next_in = source;
		bzip2uncom->avail_in = slen;
		bzip2uncom->next_out = (char*)dest;
		bzip2uncom->avail_out = g_compressbound;
		err = BZ2_bzDecompress(bzip2uncom);
		assert(err >= BZ_OK);
		inflen = g_compressbound - bzip2uncom->avail_out;
		sntDebugPrintf("sntInflate, bzip2 %u:%d.\n", slen, inflen);
		break;
	default:
		return (int)slen;
	}

	return (int)inflen;
}

int sntDeflate(unsigned int com, const char* source, char* dest,
		unsigned int slen) {

	long int deflen;
	int i;
	int err;

	switch(com){
	case SNT_COMPRESSION_LZ4:
		deflen = LZ4_compress(source, dest, (int)slen);
		sntDebugPrintf("sntDeflate, lz4 %u:%d.\n", slen, deflen);
		assert(deflen >= 0);
		break;
	case SNT_COMPRESSION_GZIP:
		deflen = g_compressbound;
		err = compress((Bytef*)dest, (uLongf*) &deflen,
				(const Bytef*)source, (uLongf) slen);
		assert(err == Z_OK);
		sntDebugPrintf("sntDeflate, gzip %u:%d.\n", slen, deflen);
		assert(deflen >= 0);
		break;
	case SNT_COMPRESSION_BZIP2:
		bzip2com->next_in = (char*)source;
		bzip2com->avail_in = slen;
		bzip2com->next_out = (char*)dest;
		bzip2com->avail_out = g_compressbound;
		err = BZ2_bzCompress(bzip2com, BZ_RUN);
		err = BZ2_bzCompress(bzip2com, BZ_FLUSH);
		assert(err >= BZ_OK);
		deflen = g_compressbound - bzip2com->avail_out;
		sntDebugPrintf("sntDeflate, bzip2 %u:%d.\n", slen, deflen);
		break;
	default:
		return (int)slen;
	}

	return (int)deflen;
}

