#include"snt_protocol_func.h"
#include"snt_log.h"
#include<assert.h>
#include<sys/socket.h>

int sntProtFuncInit(SNTConnection* connection, const SNTUniformPacket* packet) {

	int len;
	SNTInitPackage* initpack = (SNTInitPackage*)packet->totalbuf;
	SNTClientOption cliopt;

	/*	Set client options for the connection.	*/
	cliopt.ssl = connection->option->ssl;
	cliopt.symchiper = connection->option->symmetric;
	cliopt.compression = connection->option->compression;
	cliopt.benchmode = connection->option->bm_protocol_mode;
	cliopt.transprotocol = connection->option->transport_mode;
	cliopt.deltaTypes = connection->option->deltatype;
	cliopt.incdelta.i = 1;
	cliopt.duplex = connection->option->duplex;
	cliopt.invfrequency = connection->option->invfrequency;
	cliopt.payload = connection->option->payload;
	cliopt.extension = 0;
	cliopt.duration = connection->option->duration;
	cliopt.dh = connection->option->dh;

	/*	Send option.	*/
	sntInitDefaultHeader(&cliopt.header, SNT_PROTOCOL_STYPE_CLIENTOPT, sizeof(cliopt));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&cliopt);

	/*	Update connection for next incoming packet.	*/
	connection->symchiper = 0;
	connection->usecompression = cliopt.compression;

	return len;
}

int sntProtFuncCliOpt(SNTConnection* connection, const SNTUniformPacket* packet) {

	int len;
	int error;
	SNTClientOption* cliopt = (SNTClientOption*)packet->totalbuf;
	SNTReadyPacket ready;

	/*	Validate client's options.	*/
	error = sntValidateCapability(cliopt);
	if(error != SNT_ERROR_NONE){
		sntSendError(connection, error, "");
		sntLogErrorPrintf("Invalid options. denying client.\n");
		sntDisconnectSocket(connection);
		return 0;
	}

	/*	Get benchmark mode.	*/
	connection->option->bm_protocol_mode = cliopt->benchmode;
	connection->option->deltatype = cliopt->deltaTypes;
	connection->option->invfrequency = cliopt->invfrequency;
	connection->option->transport_mode = cliopt->transprotocol;
	connection->option->duration = cliopt->duration;
	connection->option->symmetric = cliopt->symchiper;
	connection->option->duplex = cliopt->duplex;

	/*	*/
	connection->option->payload = cliopt->payload;
	connection->mtubuf = malloc(connection->option->payload);
	assert(connection->mtubuf);

	/*	*/
	connection->option->compression = cliopt->compression;
	connection->usecompression = cliopt->compression;

	/*	Send Certificate. */
	if(cliopt->ssl){
		len = sntSendCertificate(g_bindconnection, connection);
	}else{

		/*	Assigned connection values.	*/
		connection->symchiper = 0;
		connection->flag |= SNT_CONNECTION_BENCH;

		/*	*/
		sntInitDefaultHeader(&ready.header, SNT_PROTOCOL_STYPE_READY, sizeof(ready));
		len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&ready);
	}

	return len;
}

int sntProtFuncCertificate(SNTConnection* connection, const SNTUniformPacket* packet) {

	int len;
	SNTCertificate* cer = (SNTCertificate*)packet->totalbuf;
	SNTSecureEstablismentPacket sec;
	char* localhash;
	void* key;

	/*	Create asymmetric.	*/
	sntDebugPrintf("%s", cer->cert);
	if(!sntASymCreateKeyFromData(connection, cer->asymchiper, cer->cert, cer->certlen)){
		fprintf(stderr, "sntASymmetricCreateKeyFromData failed.\n");
		return 0;
	}

	/*	Check if certificate has not been compromised.	*/
	localhash = malloc(sntHashGetTypeSize(cer->hashtype) + 1);
	assert(localhash);

	/*	Generate hash and compare to remote and local hash.	*/
	if(sntHash(cer->hashtype, cer->cert, cer->localhashedsize, localhash) !=
			sntHashGetTypeSize(cer->hashtype)){
		sntLogErrorPrintf("sntHash failed.\n");
		return 0;
	}

	/*	Attempt to verify signature.	*/
	if (!sntASymVerifyDigSign(connection, cer->hashtype, localhash,
			sntHashGetTypeSize(cer->hashtype), cer->hash,
			cer->encryedhashsize)) {
		sntLogErrorPrintf("None matching hashes.\n");
		return 0;
	}

	/*	Free memory and cleanup public key.	*/
	free(localhash);
	sntMemZero(&cer->certype, cer->localhashedsize);

	/*	TODO add support for condition for generate or use DH.	*/
	if(connection->option->dh > 0){
		SNTPacketHeader pack;
		sntInitDefaultHeader(&pack, SNT_PROTOCOL_STYPE_DH_REQ, sizeof(pack));
		return sntWriteSocketPacket(connection, &pack);
	}

	/*	Generate symmetric key to use.	*/
	if(!sntSymGenerateKey(connection, connection->option->symmetric)){
		sntLogErrorPrintf("sntSymmetricGenerateKey failed.\n");
		return 0;
	}

	/*	Encrypt symmetric key with asymmetric cipher.	*/
	sntSymCopyKey(connection, &key);
	sec.encrykeyblock = sntASymPubEncrypt(connection->asymchiper, key,
			sntSymKeyByteSize(connection->symchiper), sec.key, connection->asymkey);
	if(sec.encrykeyblock <= 0){
		sntLogErrorPrintf("sntAsymPubEncrypt failed.\n");
		return 0;
	}

	/*	*/
	sntMemZero(key, sntSymKeyByteSize(connection->symchiper));
	free(key);

	/*	Send packet.	*/
	sntInitDefaultHeader(&sec.header, SNT_PROTOCOL_STYPE_SECURE, sizeof(sec));
	sec.keybitlen = sntSymKeyBitSize(connection->symchiper);
	sec.symchiper = connection->symchiper;
	/*	*/
	connection->symchiper = 0;
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&sec);
	connection->symchiper = connection->option->symmetric;

	return len;
}

int sntProtFuncSecure(SNTConnection* connection, const SNTUniformPacket* packet) {

	/*	*/
	int len;
	SNTSecureEstablismentPacket* sec = (SNTSecureEstablismentPacket*)packet->totalbuf;
	unsigned char* symkey;

	/*	Decrypt symmetric key from client.	*/
	symkey = malloc(sntASymGetBlockSize(g_bindconnection->asymchiper, g_bindconnection->asymkey));
	if(!sntASymPriDecrypt(g_bindconnection->asymchiper, sec->key, sec->encrykeyblock,
			symkey, g_bindconnection->asymkey)){
		return 0;
	}
	if(!sntSymCreateFromKey(connection, sec->symchiper, symkey)){
		sntSendError(connection, SNT_ERROR_SERVER, "Couldn't extract symmetric key");
		return 0;
	}
	connection->symchiper = sec->symchiper;

	/*	Send packet.	*/
	sntSendReady(connection);

	/*	Clean up from memory.	*/
	free(symkey);
	sntMemZero(sec, sizeof(SNTUniformPacket));

	/*	TODO FIX!	*/
	connection->flag |= SNT_CONNECTION_BENCH;
	return len;
}

int sntProtFuncReady(SNTConnection* connection, const SNTUniformPacket* packet) {

	int len;
	SNTstartPacket start;

	/*	Send packet.	*/
	sntInitDefaultHeader(&start.header, SNT_PROTOCOL_STYPE_STARTTEST, sizeof(start));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&start);
	if(!sntSetTransportProcotcol(connection, connection->option->transport_mode)){
		return 0;
	}
	connection->flag |= SNT_CONNECTION_TRANS;


	/*	Start.	*/
	sntLogErrorPrintf("Starting %s benchmark.\n"
	"-----------------------------------------------\n",
	gc_bench_symbol[sntLog2MutExlusive32(connection->option->bm_protocol_mode)]);

	return len;
}

int sntProtFuncStart(SNTConnection* connection, const SNTUniformPacket* packet){

	return 1;
}

int sntProtFuncError(SNTConnection* connection, const SNTUniformPacket* packet) {

	const char* codedesc = "";
	SNTErrorPacket* error = (SNTErrorPacket*)packet;


	/*	Prevent segmentation violation.	*/
	if(error->errorcode <= sntSymbolArraySize((const void**)gs_error_sym)){
		codedesc = gs_error_sym[error->errorcode];
	}

	if(error->meslen > 0){
		sntLogErrorPrintf("Error code %d : %s | '%s'.\n", error->errorcode,
				codedesc, error->message);
	}else{
		sntLogErrorPrintf("Error code %d : %s .\n", error->errorcode, codedesc);
	}
	return 0;
}

int sntProtFuncResult(SNTConnection* connection, const SNTUniformPacket* packet) {

	const SNTResultPacket* result = (SNTResultPacket*)packet;
	sntBenchmarkPrintResult(result);
	return 1;
}

int sntProtFuncBenchmark(SNTConnection* connection, const SNTUniformPacket* packet) {

	switch(connection->option->bm_protocol_mode){
	case SNT_PROTOCOL_BM_MODE_PERFORMANCE:
		/*	Pass.	*/
		break;
	case SNT_PROTOCOL_BM_MODE_FILE:
		/*	TODO check how to pipe and redirect the data better.	*/
		/*sntLogErrorPrintf("%d.\n", sntDatagramCommandSize(&packet->header));*/
		fwrite(sntDatagramGetBlock(packet), 1, sntProtocolHeaderDatagramSize(&packet->header), stdout);
		break;
	case SNT_PROTOCOL_BM_MODE_INTEGRITY:
		printf("%s\n", sntDatagramGetBlock(packet));

		/*	Compare sequence.	*/
		switch(connection->option->deltatype){
		case SNT_DELTA_TYPE_FLOAT:
			break;
		case SNT_DELTA_TYPE_HIGHTIMESTAMP:
			break;
		case SNT_DELTA_TYPE_TIMESTAMP:
			break;
		case SNT_DELTA_TYPE_INT:
			break;
		default:
			break;
		}

		break;
	default:
		break;
	}
	return 1;
}

int sntProtFuncDHReq(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet){
	return sntSendDHpq(g_bindconnection, connection);
}

int sntProtFuncDHInit(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet){

	SNTDHInit* init = (SNTDHInit*)packet;
	const size_t packlen = sizeof(SNTDHExch);
	int len;
	void* p;
	void* g;

	/*	Extract p and g from packet.	*/
	p = &((uint8_t*)sntDatagramGetBlock(packet))[init->offset];
	g = &((uint8_t*)sntDatagramGetBlock(packet))[init->offset + init->plen];

	/*	Create diffie hellman from p and g.	*/
	if(!sntDHCreateByData(&connection->dh, p, g, init->plen, init->glen)){
		sntSendError(connection, SNT_ERROR_SERVER, "sntDHCreate failed");
		return 0;
	}

	/*	Compute.	*/
	if(!sntDHCompute(connection->dh)){
		sntSendError(connection, SNT_ERROR_SERVER, "sntDHCompute failed");
		return 0;
	}

	len = sntSendDHExch(connection);

	return len;
}

int sntProtFuncDHExch(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet){

	SNTDHExch* exch = (SNTDHExch*)packet;
	int plen;
	void *pkey;
	void* q;


	/*	If server, exhange.	*/
	if(g_bindconnection){
		if(sntSendDHExch(connection) <= 0)
			return 0;
		/*	*/
		sntSendReady(connection);
		connection->flag |= SNT_CONNECTION_BENCH;
	}

	/*	Extract key.	*/
	q = &((uint8_t*)sntDatagramGetBlock(exch))[exch->offset];
	plen = sntDHSize(connection->dh);
	pkey = malloc(plen);
	if(!sntDHGetComputedKey(connection->dh, q, pkey)){
		sntSendError(connection, SNT_ERROR_SERVER, "sntDHGetComputedKey failed");
		return 0;
	}

	/*	Create symmetric key.	*/
	if(!sntSymCreateFromKey(connection, exch->sym, pkey)){
		sntSendError(connection, SNT_ERROR_SERVER, "");
		return 0;
	}


	/*	Release.	*/
	sntDHRelease(connection->dh);
	connection->dh = NULL;

	/*	Cleanup.	*/
	sntMemZero(pkey, plen);
	free(pkey);

	return 1;
}

int sntValidateCapability(const SNTClientOption* option){

	/*	Check if options are mutually exclusive.	*/
	if (!sntIsPower2(option->benchmode) || !sntIsPower2(option->compression)
			|| !sntIsPower2(option->symchiper)
			|| !sntIsPower2(option->transprotocol)
			|| !sntIsPower2(option->deltaTypes)) {
		sntLogErrorPrintf("Non mutually exclusive option is not supported.\n");
		return SNT_ERROR_INVALID_ARGUMENT;
	}

	/*	Check options are valid to be executed.	*/
	if(option->compression && !(option->compression & g_bindconnection->option->compression)){
		sntLogErrorPrintf("compression not supported.\n");
		return SNT_ERROR_COMPRESSION_NOT_SUPPORTED;
	}

	/*	Check if secure connection is supported and requested.	*/
	if(option->ssl && g_bindconnection->option->ssl == 0){
		sntLogErrorPrintf("ssl/secure connection not supported.\n");
		return SNT_ERROR_SSL_NOT_SUPPORTED;
	}

	/*	Check if diffie hellman is supported.	*/
	if(option->dh && !(g_bindconnection->option->dh)){
		sntLogErrorPrintf("Diffie hellman supported.\n");
		return SNT_ERROR_DH_NOT_SUPPORTED;
	}

	/*	Check symmetric cipher support and requested.	*/
	if(option->symchiper && !(option->symchiper & g_bindconnection->option->symmetric)){
		sntLogErrorPrintf("cipher option not supported.\n");
		return SNT_ERROR_CIPHER_NOT_SUPPORTED;
	}

	/*	Check delta mode is supported.	*/
	if(option->deltaTypes && !(option->deltaTypes & g_bindconnection->option->deltatype)){
		sntLogErrorPrintf("%d: Invalid delta type.\n", option->deltaTypes);
		return SNT_ERROR_INVALID_ARGUMENT;
	}

	/*	Check asymmetric cipher support and requested.	*/
	if(!(option->benchmode & g_bindconnection->option->bm_protocol_mode)){
		sntLogErrorPrintf("%d: Invalid benchmark mode.\n", option->symchiper);
		return SNT_ERROR_BENCHMARK_NOT_SUPPORTED;
	}

	/*	Check if transport protocol supported.	*/
	if(!(option->transprotocol & g_bindconnection->option->transport_mode)){
		sntLogErrorPrintf("%d: Invalid transport protocol.\n", option->transprotocol);
		return SNT_ERROR_INVALID_ARGUMENT;
	}

	/*	Check if duplex protocol is supported.	*/
	if(!(option->duplex & g_bindconnection->option->duplex)){
		sntLogErrorPrintf("%d: Invalid duplex mode.\n", option->duplex);
		return SNT_ERROR_INVALID_ARGUMENT;
	}

	/*	Check version compatibility.	*/
	if(SNT_GET_MAJ_VERSION(option->header.version) < SNT_GET_MAJ_VERSION(SNT_VERSION)){
		sntLogErrorPrintf("Invalid version.\n");
		return SNT_ERROR_INCOMPATIBLE_VERSION;
	}

	/*	No error.	*/
	return SNT_ERROR_NONE;
}



int sntSendCertificate(const SNTConnection* bind, SNTConnection* client){

	int len;
	SNTCertificate cert;
	void* tmphash;

	/*	Can't execute here if asymchiper is not set.	*/
	assert(bind->asymchiper != SNT_ENCRYPTION_ASYM_NONE);

	/*	Copy public key to init packet.	*/
	sntInitDefaultHeader(&cert.header, SNT_PROTOCOL_STYPE_CERTIFICATE, sizeof(cert));
	memset(cert.cert, 0, sizeof(cert.cert));
	cert.certlen = sntASymCopyPublicKey(bind, &cert.cert[0]);
	if(cert.certlen <= 0){
		sntSendError(client, SNT_ERROR_SERVER, "");
		sntLogErrorPrintf("sntAsymmetricCopyPublicKey failed.\n");
		return 0;
	}
	sntDebugPrintf("%s.\n", cert.cert);
	cert.certype = bind->option->certificate;
	cert.asymchiper = bind->asymchiper;

	/*	Hash the certificate and meta data.	*/
	cert.hashtype = bind->option->hash;
	cert.localhashedsize = sizeof(cert.cert);
	if(!sntHash(cert.hashtype, cert.cert, cert.localhashedsize, cert.hash)){
		sntSendError(client, SNT_ERROR_SERVER, "");
		sntLogErrorPrintf("sntHash failed.\n");
		return 0;
	}

	/*	Encrypt the hash in order to prevent integrity compromising.	*/
	tmphash = malloc(sntHashGetTypeSize(cert.hashtype));
	assert(tmphash);
	memset(tmphash, 0, sntHashGetTypeSize(cert.hashtype));
	memcpy(tmphash, cert.hash, sntHashGetTypeSize(cert.hashtype));

	/*	*/
	if (!sntASymSignDigSign(bind, cert.hashtype, tmphash,
			sntHashGetTypeSize(cert.hashtype), cert.hash,
			(unsigned int*)&cert.encryedhashsize)) {
		sntSendError(client, SNT_ERROR_SERVER, "Couldn't create a digital signature");
		free(tmphash);
		return 0;
	}
	free(tmphash);

	/*	Send certificate.	*/
	len = sntWriteSocketPacket(client, (SNTUniformPacket*)&cert);

	/*	Copy bind connection asymmetric.	*/
	client->asymchiper = bind->asymchiper;
	client->asynumbits = bind->asynumbits;

	return len;
}

int sntSendDHpq(const SNTConnection* __restrict__ bind,
		SNTConnection* __restrict__ client){

	SNTDHInit* init;
	const size_t packlen = sizeof(SNTDHInit);
	const int32_t bnum = sntDHSize(bind->dh);
	int len;
	/*	*/
	uint8_t* p;
	uint8_t* g;

	assert(bind->dh);

	/*	Allocate packet.	*/
	init = malloc(packlen + bnum * 2);
	assert(init);

	/*	Initialize the packet.	*/
	sntInitDefaultHeader(&init->header, SNT_PROTOCOL_STYPE_DH_INIT, packlen + bnum * 2);

	/*	Get p and g address.	*/
	p = ((uint8_t*)init) + packlen;
	g = p + bnum;

	/*	Copy p and q.	*/
	if(!sntDHCopyCommon(bind->dh, p, g, &init->plen, &init->glen)){
		sntSendError(client, SNT_ERROR_SERVER, "Failed copy common diffie helmman p and g");
		return 0;
	}

	/*	Create copy of diffie hellman for the client connection.	*/
	if(!sntDHCreateByData(&client->dh, p, g, init->plen, init->glen)){
		sntSendError(client, SNT_ERROR_SERVER, "sntDHCreateByData failed");
		return 0;
	}

	/*	Copy p and q.	*/
	if(!sntDHCopyCommon(client->dh, p, g, &init->plen, &init->glen)){
		sntSendError(client, SNT_ERROR_SERVER, "Failed copy common diffie helmman p and g");
		return 0;
	}

	/*	Compute diffie hellman for public exchange q.	*/
	if(!sntDHCompute(client->dh)){
		sntSendError(client, SNT_ERROR_SERVER, "sntDHCompute failed");
		return 0;
	}

	/*	Assigned meta data.	*/
	init->offset = sizeof(SNTDHInit) - sizeof(SNTPacketHeader);
	init->bitsize = bnum * 8;

	/*	Send packet.	*/
	len = sntWriteSocketPacket(client, init);

	/*	Release packet from memory.	*/
	sntMemZero(init, sntProtocolPacketSize(init));
	free(init);

	return len;
}

int sntSendDHExch(SNTConnection* __restrict__ connection){

	SNTDHExch* exch;
	const size_t packlen = sizeof(SNTDHExch);
	int hdsize;
	int len;
	void* q;

	/*	*/
	hdsize = sntDHSize(connection->dh);
	exch = malloc(packlen + hdsize);
	q = ((uint8_t*)exch) + packlen;

	/*	Get exchange.	*/
	if(!sntDHGetExchange(connection->dh, q)){
		sntSendError(connection, SNT_ERROR_SERVER, "sntDHGetExchange failed");
		return 0;
	}

	/*	Compute.	*/
	sntInitDefaultHeader(&exch->header, SNT_PROTOCOL_STYPE_DH_EXCH, packlen + hdsize);
	exch->offset = sizeof(SNTDHExch) - sizeof(SNTPacketHeader);
	exch->qlen = hdsize;
	exch->sym = connection->option->symmetric;

	/*	Send packet.	*/
	len = sntWriteSocketPacket(connection, exch);

	/*	Release.	*/
	sntMemZero(exch, sntProtocolPacketSize(exch));
	free(exch);

	return len;
}

int sntSendReady(SNTConnection* __restrict__ connection){

	SNTReadyPacket ready;
	int len;

	/*	Send packet.	*/
	sntInitDefaultHeader(&ready.header, SNT_PROTOCOL_STYPE_READY, sizeof(ready));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&ready);

	return len;
}

int sntSendError(const SNTConnection* connection, int code,
		const char* message) {
	SNTErrorPacket error;

	sntInitDefaultHeader(&error.header, SNT_PROTOCOL_STYPE_ERROR, sizeof(error));

	/*	Assign error packet.	*/
	error.errorcode = code;
	error.meslen = (unsigned int)strlen(message);
	memcpy(error.message, message, error.meslen);
	error.message[error.meslen] = '\0';

	return sntWriteSocketPacket(connection, (SNTUniformPacket*)&error);
}

int sntSendBenchMarkResult(const SNTConnection* connection, const SNTResultPacket* result){
	return sntWriteSocketPacket(connection, result);
}

