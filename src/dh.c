#include"snt_dh.h"
#include"snt_log.h"
#include"snt_encryption.h"
#include<openssl/ssl.h>
#include<assert.h>

int sntDHCreate(sntDH** __restrict__ dh, int numbits){
	int codes;

	/*	Create DH.*/
	*dh = DH_new();

	/*	Generate Diffie hellman.	*/
	if(!DH_generate_parameters_ex((DH*)*dh, numbits, DH_GENERATOR_2,
			NULL)){
		sntSSLPrintError();
		return 0;
	}

	/*	Check.	*/
	if(!DH_check((DH*)*dh, &codes)){
		sntLogErrorPrintf("DH_check failed.\n");
		sntSSLPrintError();
		sntDHRelease(*dh);
		return 0;
	}

	/*	Check error code.	*/
	if((codes & DH_CHECK_P_NOT_SAFE_PRIME) || (codes & DH_CHECK_P_NOT_PRIME)){
		sntLogErrorPrintf("DH_check failed.\n");
		sntSSLPrintError();
		sntDHRelease(*dh);
		return 0;
	}

	return 1;
}

int sntDHCreateByData(sntDH** __restrict__ dh, const void* __restrict__ p,
		const void* __restrict__ g, uint32_t plen, uint32_t glen){

	/*	Create DH.*/
	*dh = DH_new();

	/*	Assign p key.	*/
	BIGNUM* pkey = BN_bin2bn(p, plen, NULL);
	BIGNUM* gkey = BN_bin2bn(g, glen, NULL);

	if(!DH_set0_pqg(*dh, pkey, NULL, gkey)){
		sntLogErrorPrintf("BN_bin2bn failed for p.\n");
		sntSSLPrintError();
		sntDHRelease(*dh);
		return 0;
	}

	int rc, codes = 0;
	rc = DH_check(*dh, &codes);
	if(!rc){
		sntSSLPrintError();
		sntDHRelease(*dh);
		return 0;
	}

	/*	Check error code.	*/
	if((codes & DH_CHECK_P_NOT_SAFE_PRIME) || (codes & DH_CHECK_P_NOT_PRIME)){
		sntLogErrorPrintf("DH_check failed.\n");
		sntSSLPrintError();
		sntDHRelease(*dh);
		return 0;
	}

	return 1;
}

int sntDHCreateFromPEMFile(sntDH** __restrict__ dh, const char* path){

	BIO* bio;
	unsigned int asym = 0;

	/*  Load file.  */
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, path) <= 0) {
		sntSSLPrintError();
		return 0;
	}

	/*  Load diffie hellman.    */
	*dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	if (*dh == NULL) {
		BIO_free(bio);
		sntSSLPrintError();
		return 0;
	}

	/*  Release.    */
	BIO_free(bio);

	return 1;
}

int sntDHSize(const sntDH* dh){
	return DH_size(dh);
}

void sntDHRelease(sntDH* dh){
	DH_free(dh);
}

int sntDHCopyCommon(sntDH* __restrict__ dh, void* __restrict__ p,
		void* __restrict__ g, uint32_t* __restrict__ pplen,
		uint32_t* __restrict__ pglen){

	/*	Compute length for p and g.	*/

	const int plen = BN_num_bytes(DH_get0_p(dh));
	const int glen = BN_num_bytes(DH_get0_g(dh));

		/*	*/
	assert(p && g && plen && glen);

	/*	Invalid g or p.	*/
	if(glen <= 0 || plen <= 0)
		return 0;

	/*	Copy number length in bytes.	*/
	*pplen = plen;
	*pglen = glen;

	/*	Copy p.	*/
	if(!BN_bn2bin(DH_get0_p(dh), p)){
		sntLogErrorPrintf("BN_bn2bin failed for p.\n");
		return 0;
	}
	/*	Copy g.	*/
	if(!BN_bn2bin(DH_get0_g(dh), g)){
		sntLogErrorPrintf("BN_bn2bin failed for g.\n");
		return 0;
	}

	return 1;
}

int sntDHCompute(sntDH* dh){

	/*	Compute public key for exchanging.	*/
	if(!DH_generate_key((DH*)dh)){
		sntLogErrorPrintf("DH_generate_key failed.\n");
		sntSSLPrintError();
		return 0;
	}

	return 1;
}

int sntDHGetExchange(sntDH* __restrict__ dh,
		void* __restrict__ ex){

	/*	Copy public number binary to ex.	*/
	
	if(!BN_bn2bin(DH_get0_pub_key(dh), ex)){
		sntLogErrorPrintf("BN_bn2bin failed for p.\n");
		sntSSLPrintError();
		return 0;
	}

	return 1;
}

int sntDHGetComputedKey(sntDH* __restrict__ dh, const void* q,
		void* __restrict__ key) {

	BIGNUM* pub;
	const int plen = BN_num_bytes(DH_get0_p(dh));

	/*	Create bignum from binary.	*/
	pub = BN_bin2bn(q, plen, NULL);
	if(!pub){
		sntSSLPrintError();
		return 0;
	}

	/*	Compute shared key.	*/
	if(!DH_compute_key(key, pub, dh)){
		sntSSLPrintError();
		return 0;
	}

	return 1;
}