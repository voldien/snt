#include"snt_protocol_func.h"
#include"snt_log.h"
#include<assert.h>
#include<sys/socket.h>

int sntProtFuncInit(SNTConnection* connection, SNTUniformPacket* packet) {

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
	cliopt.duplex = 0;
	cliopt.invfrequency = connection->option->invfrequency;
	cliopt.playload = connection->option->payload;
	cliopt.extension = 0;

	/*	Send option.	*/
	sntInitDefaultHeader(&cliopt.header, SNT_PROTOCOL_STYPE_CLIENTOPT, sizeof(cliopt));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&cliopt);

	/*	Update connection for next incoming packet.	*/
	connection->symchiper = 0;
	connection->usecompression = cliopt.compression;

	return len;
}

int sntProtFuncCliOpt(SNTConnection* connection, SNTUniformPacket* packet) {

	int len;
	int error;
	SNTClientOption* cliopt = (SNTClientOption*)packet->totalbuf;
	SNTReadyPacket ready;

	/*	Validate client's options.	*/
	error = sntValidateCapability(cliopt);
	if(error != SNT_ERROR_NONE){
		sntSendError(connection, error, "");
		fprintf(stderr, "Invalid options. denying client.\n");
		sntDisconnectSocket(connection);
		return 0;
	}

	/*	Get benchmark mode.	*/
	connection->option->bm_protocol_mode = cliopt->benchmode;
	connection->option->deltatype = cliopt->deltaTypes;
	connection->option->invfrequency = cliopt->invfrequency;
	connection->option->transport_mode = cliopt->transprotocol;

	connection->option->payload = cliopt->playload;
	connection->mtubuf = malloc(connection->option->payload);
	assert(connection->mtubuf);


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

int sntProtFuncCertificate(SNTConnection* connection, SNTUniformPacket* packet) {

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
	localhash = malloc(sntGetHashTypeSize(cer->hashtype) + 1);
	assert(localhash);

	/*	Generate hash and compare to remote and local hash.	*/
	if(sntHash(cer->hashtype, cer->cert, cer->localhashedsize, localhash) !=
			sntGetHashTypeSize(cer->hashtype)){
		fprintf(stderr, "sntHash failed.\n");
		return 0;
	}
	if (!sntASymVerifyDigSign(connection, cer->hashtype, localhash,
			sntGetHashTypeSize(cer->hashtype), cer->hash,
			cer->encryedhashsize)) {
		fprintf(stderr, "None matching hashes.\n");
		return 0;
	}

	/*	Free memory and cleanup public key.	*/
	free(localhash);
	memset(&cer->certype, 0, cer->localhashedsize);


	/*	Generate symmetric key to use.	*/
	if(!sntSymGenerateKey(connection, connection->option->symmetric)){
		fprintf(stderr, "sntSymmetricGenerateKey failed.\n");
		return 0;
	}

	/*	Encrypt symmetric key with asymmetric cipher.	*/
	sntSymCopyKey(connection, &key);
	sec.encrykeyblock = sntASymPubEncrypt(connection->asymchiper, key,
			sntSymKeyByteSize(connection->symchiper), sec.key, connection->asymkey);
	if(sec.encrykeyblock <= 0){
		fprintf(stderr, "sntAsymPubEncrypt failed.\n");
		return 0;
	}
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

int sntProtFuncSecure(SNTConnection* connection, SNTUniformPacket* packet) {

	/*	*/
	int len;
	SNTReadyPacket ready;
	SNTSecureEstablismentPacket* sec = (SNTSecureEstablismentPacket*)packet->totalbuf;
	unsigned char* symkey;

	/*	Decrypt symmetric key from client.	*/
	symkey = malloc(sntASymGetBlockSize(g_bindconnection->asymchiper, g_bindconnection->asymkey));
	if(!sntASymPriDecrypt(g_bindconnection->asymchiper, sec->key, sec->encrykeyblock,
			symkey, g_bindconnection->asymkey)){
		return 0;
	}
	if(!sntSymCreateFromKey(connection, sec->symchiper, symkey)){
		sntSendError(connection, 0, "");
		return 0;
	}
	connection->symchiper = sec->symchiper;

	/*	Send packet.	*/
	sntInitDefaultHeader(&ready.header, SNT_PROTOCOL_STYPE_READY, sizeof(ready));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&ready);

	/*	Clean up from memory.	*/
	free(symkey);
	memset(sec, 0, sizeof(SNTUniformPacket));

	/*	TODO FIX!	*/
	connection->flag |= SNT_CONNECTION_BENCH;
	return len;
}

int sntProtFuncReady(SNTConnection* connection, SNTUniformPacket* packet) {

	int len;
	SNTstartPacket start;

	/*	Send packet.	*/
	sntInitDefaultHeader(&start.header, SNT_PROTOCOL_STYPE_STARTTEST, sizeof(start));
	len = sntWriteSocketPacket(connection, (SNTUniformPacket*)&start);
	if(!sntSetTransportProcotcol(connection, connection->option->transport_mode)){
		return 0;
	}
	connection->flag |= SNT_CONNECTION_TRANS;

	return len;
}

int sntProtFuncStart(SNTConnection* connection, SNTUniformPacket* packet){

	return 1;
}

int sntProtFuncError(SNTConnection* __restrict__ connection,
		SNTUniformPacket* __restrict__ packet){
	SNTErrorPacket* error = (SNTErrorPacket*)packet;

	fprintf(stderr, "Error code %d, %s.\n", error->errorcode, error->message);
	return 0;
}

int sntProtFuncBenchmark(SNTConnection* connection, SNTUniformPacket* packet) {

	switch(connection->option->bm_protocol_mode){
	case SNT_PROTOCOL_BM_MODE_PERFORMANCE:
		/*	Pass.	*/
		break;
	case SNT_PROTOCOL_BM_MODE_FILE:
		/*	TODO check how to pipe and redirect the data better.	*/
		/*fprintf(stderr, "%d.\n", sntDatagramCommandSize(&packet->header));*/
		fwrite(packet->buf, 1, sntDatagramCommandSize(&packet->header), stdout);
		break;
	case SNT_PROTOCOL_BM_MODE_INTEGRITY:
		printf("%s\n", packet->buf);
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
		/*	Compare sequence.	*/
		break;
	default:
		break;
	}
	return 1;
}

int sntValidateCapability(const SNTClientOption* option){

	/*	Check options are valid to be executed.	*/
	if(option->compression && g_bindconnection->option->compression == 0){
		fprintf(stderr, "compression not supported.\n");
		return SNT_ERROR_COMPRESSION_NOT_SUPPORTED;
	}

	if(option->ssl && g_bindconnection->option->ssl == 0){
		fprintf(stderr, "ssl/secure connection not supported.\n");
		return SNT_ERROR_SSL_NOT_SUPPORTED;
	}

	if(option->benchmode & (~SNT_PROTOCOL_BM_MODE_ALL)){
		fprintf(stderr, "%d: Invalid benchmark mode.\n", option->benchmode);
		return SNT_ERROR_INVALID_ARGUMENT;
	}

	if(SNT_GET_MAJ_VERSION(option->header.version) < SNT_GET_MAJ_VERSION(SNT_VERSION)){
		fprintf(stderr, "Invalid version.\n");
		return SNT_ERROR_INCOMPATIBLE_VERSION;
	}
	return SNT_ERROR_NONE;
}



int sntSendCertificate(const SNTConnection* bind, SNTConnection* client){

	int len;
	SNTCertificate cert;
	void* tmphash;
	assert(bind->asymchiper != SNT_ENCRYPTION_ASYM_NONE);

	/*	Copy public key to init packet.	*/
	sntInitDefaultHeader(&cert.header, SNT_PROTOCOL_STYPE_CERTIFICATE, sizeof(cert));
	memset(cert.cert, 0, sizeof(cert.cert));
	cert.certlen = sntASymCopyPublicKey(bind, &cert.cert[0]);
	if(cert.certlen <= 0){
		fprintf(stderr, "sntAsymmetricCopyPublicKey failed.\n");
		return 0;
	}
	sntDebugPrintf("%s.\n", cert.cert);
	cert.certype = SNT_CERTIFICATE_RSA;
	cert.asymchiper = bind->asymchiper;

	/*	Hash the certificate and meta data.	*/
	cert.hashtype = bind->option->hash;
	cert.localhashedsize = sizeof(cert.cert);
	sntHash(cert.hashtype, cert.cert, cert.localhashedsize, cert.hash);

	/*	Encrypt the hash in order to prevent integrity compromising.	*/
	tmphash = malloc(sntGetHashTypeSize(cert.hashtype));
	assert(tmphash);
	memset(tmphash, 0, sntGetHashTypeSize(cert.hashtype));
	memcpy(tmphash, cert.hash, sntGetHashTypeSize(cert.hashtype));

	/*	*/
	if (!sntASymSignDigSign(bind, cert.hashtype, tmphash,
			sntGetHashTypeSize(cert.hashtype), cert.hash,
			(unsigned int*)&cert.encryedhashsize)) {
		sntSendError(client, SNT_ERROR_SERVER, "Couldn't create digital signature");
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

int sntSendError(const SNTConnection* connection, int code,
		const char* message) {
	SNTErrorPacket error;
	sntInitDefaultHeader(&error.header, SNT_PROTOCOL_STYPE_ERROR, sizeof(error));
	error.errorcode = code;
	error.meslen = (unsigned int)strlen(message);
	memcpy(error.message, message, error.meslen);
	error.message[error.meslen] = '\0';
	return sntWriteSocketPacket(connection, (SNTUniformPacket*)&error);
}



