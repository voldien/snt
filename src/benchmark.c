#include"snt_benchmark.h"
#include"snt_utility.h"
#include"snt_log.h"
#include"snt_protocol_func.h"
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

pthread_t sntCreateBenchmarkThread(unsigned int mode, SNTConnection* patt){

	pthread_t thread;					/*	*/
	pthread_attr_t attr;				/*	*/
	snt_client_thread func;				/*	*/
	size_t  guardsize;					/*	*/
	struct sched_param schparam;		/*	*/
	int err;							/*	*/

	switch(mode){
	case SNT_PROTOCOL_BM_MODE_PERFORMANCE:
		sntVerbosePrintf("Creating Performance benchmark thread.\n");
		func = sntClientPerformanceBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_INTEGRITY:
		sntVerbosePrintf("Creating Integrity benchmark thread.\n");
		func = sntClientIntegrityBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_FILE:
		sntVerbosePrintf("Creating file benchmark thread.\n");
		func = sntClientFileBenchmark;
		break;
	case SNT_PROTOCOL_BM_MODE_UNKNOWN:
	default:
		fprintf(stderr, "Invalid benchmark mode, %x.\n", mode);
		return NULL;
	}

	/*	Thread attributes.	*/
	if(pthread_attr_init(&attr) != 0){
		fprintf(stderr, "pthread_attr_init failed, %s.\n", strerror(errno));
	}

	/*	Set guardsize.	*/
	guardsize = (1 << 14);
	if(pthread_attr_setguardsize(&attr, guardsize) != 0){
		fprintf(stderr, "pthread_attr_getguardsize failed, %s.\n", strerror(errno));
	}

	/*	Thread schedule priority.	*/
	schparam.__sched_priority = 0;
	err = pthread_attr_setschedparam(&attr, &schparam);
	if(err != 0){
		fprintf(stderr, "pthread_attr_setschedparam failed, %d.\n", err);
	}

	/*	Set affinity. TODO fix!	*/
	/*err = pthread_attr_setaffinity_np();	*/
	/*sched_getaffinity(0, 1, )	*/

	/*	Create thread.	*/
	sntVerbosePrintf("Creating benchmark thread.\n");
	err = pthread_create(&thread, &attr, func, patt);
	if( err != 0 ){
		fprintf(stderr, "Failed to create thread for client, %s.\n", strerror(errno));
	}

	/*	Release thread once done.	*/
	if( pthread_detach(thread) != 0){
		fprintf(stderr, "pthread_detach failed, %s.\n", strerror(errno));
	}

	err = pthread_attr_destroy(&attr);
	if(err != 0){
		fprintf(stderr, "pthread_attr_destroy failed, %s.\n", strerror(errno));
	}

	return thread;
}

int sntWaitBenchmark(SNTConnection* connection){

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
	connection->flag |= SNT_CONNECTION_TRANS;

	return 1;
}

void sntWaitFrequency(const SNTConnectionOption* conopt){
	sntNanoSleep(conopt->invfrequency);
}

void* sntClientIntegrityBenchmark(void* patt){

	/*	*/
	SNTConnection* con = patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	size_t clne;
	int len = 0;
	SNTDelta delta = {0};
	SNTDelta inc = {1};
	long int total = 0;
	long int starttime = 0;

	/*	Clear buffer in order remove
	 *  any sensitive information in the stack.	*/
	pack = (SNTUniformPacket*)con->mtubuf;
	clne = con->option->payload;
	memset(pack, 0, clne);
	sntInitDefaultHeader((SNTPacketHeader*) &pack->header,
			SNT_PROTOCOL_STYPE_BENCHMARK, 0);

	/*	Wait intill the client send start packet.	*/
	if(sntWaitBenchmark(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	Start.	*/
	fprintf(stdout, "Starting benchmark.\n"
	"-----------------------------------------------\n");
	starttime = sntGetNanoTime();
	while(con->flag & SNT_CONNECTION_BENCH){
		len = sntGenerateDeltaTypeInc(con->option->deltatype, (char*)pack->buf, &delta, &inc);

		pack->buf[len] = '\0';
		len++;
		pack->header.len = len + sizeof(SNTPacketHeader);

		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		total += len;

		/*	*/
		sntWaitFrequency(conopt);
	}

	printf("number of packet failure : %d.\n", g_nfailure);
	fprintf(stdout, "Kbit %ld.\n", (total * 8) / 1024 );
	fprintf(stdout, "Ending benchmark.\n"
	"-----------------------------------------------\n");

	sntDisconnectSocket(con);
	return NULL;
}

void* sntClientPerformanceBenchmark(void* patt){

	SNTConnection* con = patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	float duration;
	size_t clne;
	int len = 0;
	long int total = 0;
	long int startime = 0;

	/*	Clear buffer in order remove
	 *  any sensitive information.	*/
	pack = (SNTUniformPacket*)con->mtubuf;
	clne = con->option->payload;
	memset(pack, 0, clne);
	sntInitDefaultHeader(&pack->header, SNT_PROTOCOL_STYPE_BENCHMARK, clne);

	/*	Wait intill the client sends start packet.	*/
	if(sntWaitBenchmark(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	*/
	fprintf(stdout, "Starting performance benchmark.\n"
	"-----------------------------------------------\n");
	startime = sntGetNanoTime();
	while(con->flag & SNT_CONNECTION_BENCH){
		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		total += len;

		/*	*/
		sntWaitFrequency(conopt);
	}

	/*	*/
	duration = (float)(sntGetNanoTime() -  startime) / 1E9f;
	fprintf(stdout, "%ld Mbit sent.\n", (total * 8) / (1024 * 1024) );
	fprintf(stdout, "%3f Mbit average.\n", ( (total * 8) / (1024 * 1024) ) / duration );
	fprintf(stdout, "End of benchmark.\n"
	"-----------------------------------------------\n");

	sntDisconnectSocket(con);
	return NULL;
}

void* sntClientFileBenchmark(void* patt){

	SNTConnection* con = (SNTConnection*)patt;
	SNTConnectionOption* conopt = con->option;
	SNTUniformPacket* pack;
	float duration;
	int len;
	size_t flen;
	long int total = 0;
	long int startime = 0;
	uint32_t asyncblock;
	FILE* f;

	pack = (SNTUniformPacket*)con->mtubuf;
	asyncblock = con->option->payload;

	/*	Clear buffer in order remove
	 *  any sensitive information.	*/
	memset(pack, 0, asyncblock);
	sntInitHeader(&pack->header, SNT_PROTOCOL_STYPE_BENCHMARK, asyncblock);
	asyncblock = sntDatagramCommandSize(&pack->header);

	/*	Open file.	*/
	sntVerbosePrintf("Opening duplicate file stream.\n");

	f = fopen(g_filepath, "rb");
	if(!f){
		sntSendError(con, SNT_ERROR_SERVER, "Error failed to open file");
		return NULL;
	}
	fseek(f, 0, SEEK_SET);

	/*	Wait intill the client send start packet.	*/
	if(sntWaitBenchmark(con) == 0){
		sntDisconnectSocket(con);
		return NULL;
	}

	/*	*/
	fprintf(stdout, "Starting file benchmark.\n"
	"-----------------------------------------------\n");
	startime = sntGetNanoTime();
	while((flen = fread(pack->buf, 1, asyncblock, f)) > 0 && (con->flag & SNT_CONNECTION_BENCH )){
		pack->header.len = flen + sizeof(SNTPacketHeader);

		len = sntWriteSocketPacket(con, pack);
		if( len <= 0){
			break;
		}
		total += len;

		/*	*/
		sntWaitFrequency(conopt);
	}

	/*	End connection.	*/
	duration = (float)(sntGetNanoTime() -  startime) / 1E9f;
	fprintf(stdout, "%ld Mbit sent.\n", (total * 8) / (1024 * 1024) );
	fprintf(stdout, "%3f Mbit average.\n", ( (total * 8) / (1024 * 1024) ) / duration );
	fprintf(stdout, "End of benchmark.\n"
	"-----------------------------------------------\n");
	/*sntSendBenchMarkResult(connection);	*/

	fclose(f);
	sntDisconnectSocket(con);
	return NULL;
}

