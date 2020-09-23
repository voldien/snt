#include"snt_benchmark.h"
#include"snt_protocol.h"
#include"snt_utility.h"
#include"snt_log.h"
#include"snt_protocol_func.h"
#include"snt_schd.h"
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include<errno.h>
#include<time.h>

const char* gc_bench_symbol[] = {
		"",
		"performance",
		"integrity",
		"file",
		NULL
};

typedef void* (*snt_client_thread)(void* patt);

pthread_t sntBenchmarkCreateThread(unsigned int mode, SNTConnection* patt){

	pthread_t thread;					/*	*/
	pthread_attr_t attr;				/*	*/
	snt_client_thread func;				/*	*/
	size_t  guardsize;					/*	*/
	struct sched_param schparam;        /*	*/
	int err;                            /*	*/
	unsigned int cpu,cores,size;        /*	*/

	switch(mode){
	case SNT_PROTOCOL_BM_MODE_PERFORMANCE:
		func = sntClientPerformanceBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_INTEGRITY:
		func = sntClientIntegrityBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_FILE:
		func = sntClientFileBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_UNKNOWN:
	default:
		sntLogErrorPrintf("Invalid benchmark mode, %x.\n", mode);
		return 0;
	}

	/*	Verbose benchmark mode.	*/
	sntVerbosePrintf("Creating %s benchmark thread.\n", gc_bench_symbol[sntLog2MutExlusive32(mode)]);

	/*	Thread attributes.	*/
	if(pthread_attr_init(&attr) != 0){
		sntLogErrorPrintf("pthread_attr_init failed, %s.\n", strerror(errno));
		return 0;
	}

	/*	Set guardsize. 	*/
	guardsize = (1 << 14);
	if(pthread_attr_setguardsize(&attr, guardsize) != 0){
		sntLogErrorPrintf("pthread_attr_getguardsize failed, %s.\n", strerror(errno));
		return 0;
	}

	/*	Thread schedule priority.	*/
	schparam.__sched_priority = 0;
	err = pthread_attr_setschedparam(&attr, &schparam);
	if(err != 0){
		sntLogErrorPrintf("pthread_attr_setschedparam failed, %d.\n", err);
		return 0;
	}

	/*	Thread schedule priority.	*/
	err = pthread_attr_setschedpolicy(&attr, SCHED_RR);
	if(err != 0){
		sntLogErrorPrintf("pthread_attr_setschedpolicy failed, %d.\n", err);
		return 0;
	}

	/*	Set affinity.	*/
	sntSchdGetAffinity(&cpu, &cores, &size);
	if(!sntSchdSetThreadAttrAffinity(&attr, cpu, cores, size)){
		sntLogErrorPrintf("sntSchdSetThreadAttrAffinity failed.\n");
		return 0;
	}

	/*	Allocate benchmark session.	*/
	patt->session = malloc(sizeof(SNTBenchmarkSession));
	sntMemZero(patt->session, sizeof(SNTBenchmarkSession));

	/*	Create thread.	*/
	sntDebugPrintf("Creating benchmark thread.\n");
	err = pthread_create(&thread, &attr, func, patt);
	if( err != 0 ){
		sntLogErrorPrintf("Failed to create thread for client, %s.\n", strerror(errno));
		return 0;
	}

	/*	Release thread once done.	*/
	if( pthread_detach(thread) != 0){
		sntLogErrorPrintf("pthread_detach failed, %s.\n", strerror(errno));
		return 0;
	}

	/*	Release attribute resources.	*/
	err = pthread_attr_destroy(&attr);
	if(err != 0){
		sntLogErrorPrintf("pthread_attr_destroy failed, %s.\n", strerror(errno));
	}

	return thread;
}

int sntBenchmarkWait(SNTConnection* connection){

	int len;				/*	*/
	SNTUniformPacket pack;	/*	*/

	/*	Wait in till start packet */
	memset(&pack, 0, sizeof(pack));
	do{
		len = sntReadSocketPacket(connection, &pack);
		if(len <= 0){
			return 0;
		}

	}while(pack.header.stype != SNT_PROTOCOL_STYPE_STARTTEST);

	/*	Set transport layer.	*/
	if(!sntSetTransportProcotcol(connection, connection->option->transport_mode)){
		sntSendError(connection, SNT_ERROR_SERVER, "Transport mode failed");
		return 0;
	}

	/*  Enable transport mode.  */
	connection->flag |= SNT_CONNECTION_TRANS;

	return 1;
}

void sntWaitFrequency(const SNTConnectionOption* conopt){
	sntNanoSleep(conopt->invfrequency);
}

int sntDurationExpired(uint64_t elapse, const SNTConnectionOption* option){
	return elapse > option->duration;
}

void sntBenchmarkPrintResult(const SNTResultPacket* result){

	float duration;

	/*	Benchmark duration.	*/
	duration = (float)result->elapse / (float)sntGetTimeResolution();

	/*	Display benchmark result.	*/
	fprintf(stderr, "%f duration.\n", duration);
	fprintf(stderr, "%3f Mbit sent.\n", (float)(result->nbytes * 8) / (float)(1024 * 1024));
	fprintf(stderr, "%3f Mbit average.\n",
			((float)(result->nbytes * 8) / (float)(1024 * 1024)) / duration);
	fprintf(stderr, "%ld packets sent.\n", result->npackets);
	fprintf(stderr, "End of benchmark.\n"
	"-----------------------------------------------\n");
}

void sntBenchmarkPrintSessionResult(const SNTBenchmarkSession* session){

	float duration;

	/*	Benchmark duration.	*/
	duration = (float)session->elapse / (float)sntGetTimeResolution();

	/*	Display benchmark result.	*/
	fprintf(stderr, "%f duration.\n", duration);
	fprintf(stderr, "%3f Mbit sent.\n", (float)(session->nbytes * 8) / (float)(1024 * 1024));
	fprintf(stderr, "%3f Mbit average.\n",
			((float)(session->nbytes * 8) / (float)(1024 * 1024)) / duration);
	fprintf(stderr, "%ld packets sent.\n", session->npackets);
	fprintf(stderr, "%ld packets out of order.\n", session->ofo);
	fprintf(stderr, "End of benchmark.\n"
	"-----------------------------------------------\n");
}

void sntBenchmarkEnd(SNTConnection* __restrict__ connection,
		SNTResultPacket* __restrict__ result){

	/*	Get time resolution.	*/
	result->timeres = (uint64_t)sntGetTimeResolution();

	/*	Send benchmark result.	*/
	sntSendBenchMarkResult(connection, result);

	/*	Display print result on server.	*/
	sntBenchmarkPrintResult(result);

	/*	Close the session.	*/
	sntDisconnectSocket(connection);
}

void* sntClientIntegrityBenchmark(void* patt){

	/*	*/
	SNTResultPacket result;
	SNTConnection* con = patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	SNTBenchmarkSession* session = con->session;
	size_t clne;
	int len = 0;
	SNTDelta delta = {0};
	SNTDelta inc = {1};
	long int starttime = 0;

	memset(&result, 0, sizeof(result));
	/*	Clear buffer in order remove
	 *  any sensitive information in the stack.	*/
	pack = (SNTUniformPacket*)con->mtubuf;
	clne = con->option->payload;
	memset(pack, 0, clne);
	sntInitDefaultHeader((SNTPacketHeader*) &pack->header,
			SNT_PROTOCOL_STYPE_BENCHMARK, 0);

	/*	Wait intill the client send start packet.	*/
	if(sntBenchmarkWait(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	Start.	*/
	fprintf(stdout, "Starting integrity benchmark.\n"
	"-----------------------------------------------\n");
	starttime = sntGetNanoTime();
	while(sntIsBenchEnable(con) && !sntDurationExpired(sntGetNanoTime() - starttime, conopt)){

		len = sntGenerateDeltaTypeInc(con->option->deltatype, (char*)pack->buf, &delta, &con->option->delta);
		len++;
		pack->header.len = len + sizeof(SNTPacketHeader);

		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		result.nbytes += len;
		result.npackets++;

		/*	Wait.	*/
		sntWaitFrequency(conopt);
	}

	/*	*/
	sntInitDefaultHeader(&result.header, SNT_PROTOCOL_STYPE_RESULT, sizeof(result));
	result.elapse = sntGetNanoTime() - starttime;
	result.type = 0;

	/*  End benchmark.  */
	sntBenchmarkEnd(con, &result);
	return NULL;
}

void* sntClientPerformanceBenchmark(void* patt){

	SNTConnection* con = patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	SNTResultPacket result;
	size_t clne;
	int len = 0;
	uint64_t starttime = 0;

	memset(&result, 0, sizeof(result));
	/*	Clear buffer in order remove
	 *  any sensitive information.	*/
	pack = (SNTUniformPacket*)con->mtubuf;
	clne = con->option->payload;
	memset(pack, 0, clne);
	sntInitDefaultHeader(&pack->header, SNT_PROTOCOL_STYPE_BENCHMARK, clne);

	/*	Wait intill the client sends start packet.	*/
	if(sntBenchmarkWait(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	*/
	fprintf(stdout, "Starting performance benchmark.\n"
	"-----------------------------------------------\n");
	starttime = sntGetNanoTime();
	while(sntIsBenchEnable(con) && !sntDurationExpired(sntGetNanoTime() - starttime, conopt)){
		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		result.nbytes += (uint64_t)len;
		result.npackets++;

		/*	Wait.	*/
		sntWaitFrequency(conopt);
	}

	/*	*/
	sntInitDefaultHeader(&result.header, SNT_PROTOCOL_STYPE_RESULT, sizeof(result));
	result.elapse = (sntGetNanoTime() - starttime);
	result.type = 0;

	/*  End benchmark.  */
	sntBenchmarkEnd(con, &result);
	return NULL;
}

void* sntClientFileBenchmark(void* patt){

	SNTConnection* con = (SNTConnection*)patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	SNTResultPacket result;
	int len;
	size_t flen;
	long int starttime = 0;
	uint32_t asyncblock;
	FILE* f;

	pack = (SNTUniformPacket*)con->mtubuf;
	asyncblock = con->option->payload;
	memset(&result, 0, sizeof(result));

	/*	Clear buffer in order remove
	 *  any sensitive information.	*/
	memset(pack, 0, asyncblock);
	sntInitHeader(&pack->header, SNT_PROTOCOL_STYPE_BENCHMARK, asyncblock);
	asyncblock = sntProtocolHeaderDatagramSize(&pack->header);

	/*	Open file.	*/
	sntVerbosePrintf("Opening duplicate file stream.\n");

	/*	*/
	f = fopen(g_filepath, "rb");
	if(!f){
		sntSendError(con, SNT_ERROR_SERVER, "Error failed to open file");
		return NULL;
	}
	fseek(f, 0, SEEK_SET);

	/*	Wait intill the client send start packet.	*/
	if(sntBenchmarkWait(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	*/
	fprintf(stdout, "Starting file benchmark.\n"
	"-----------------------------------------------\n");
	starttime = sntGetNanoTime();
	while((flen = fread(pack->buf, 1, asyncblock, f)) > 0 && (con->flag & SNT_CONNECTION_BENCH )){
		pack->header.len = flen + sizeof(SNTPacketHeader);

		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		result.nbytes += (uint64_t)len;
		result.npackets++;

		/*	Wait.	*/
		sntWaitFrequency(conopt);
	}

	/*	*/
	sntInitDefaultHeader(&result.header, SNT_PROTOCOL_STYPE_RESULT, sizeof(result));
	result.elapse = (uint64_t)(sntGetNanoTime() - starttime);
	result.type = 0;

	/*	End benchmark.  */
	fclose(f);
	sntBenchmarkEnd(con, &result);
	return NULL;
}
