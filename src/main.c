#include "snt_benchmark.h"
#include "snt_utility.h"
#include "snt_debug.h"
#include "snt_protocol.h"
#include "snt_log.h"
#include <signal.h>
#include <netdb.h>
#include <sys/select.h>


static void snt_release(void){

	unsigned int i;

	if( g_bindconnection){
		sntDisconnectSocket(g_bindconnection);
		g_bindconnection = NULL;
	}
	/*	cleanup.	*/
	if(g_contable && g_connectionpool){
		for( i = 0; i < FD_SETSIZE; i++){
			if(g_contable[i] != NULL){
				sntDisconnectSocket(g_contable[i]);
			}
		}
		free(g_contable);
		g_contable = NULL;
		free(g_threadtable);
		g_threadtable = NULL;
	}

	if(g_connectionpool){
		sntPoolFree(g_connectionpool);
		g_connectionpool = NULL;
	}
}

/*	signal interrupts.	*/
void snt_catch(int signal){

	/*	Ignore SIGPIPE.	*/
	if(signal == SIGPIPE)
		return;

	/*	*/
	sntDebugPrintf("Catch signal : %d.\n", signal);
	snt_release();
	exit(EXIT_SUCCESS);
}

int main(int argc, const char** argv){

	/*	*/
	SNTConnectionOption conopt;				/*	*/
	char host[256] = {"127.0.0.1"};			/*	*/
	unsigned int port = SNT_DEFAULT_PORT;	/*	*/

	/*	Read user input argument.	*/
	sntReadArgument(argc, argv, host, &port, &conopt);

	/*	signal callback.	*/
	signal(SIGINT, snt_catch);
	signal(SIGFPE, snt_catch);
	signal(SIGTERM, snt_catch);
	signal(SIGPIPE, snt_catch);
	signal(SIGABRT, snt_catch);
	atexit(snt_release);

	/*	Create server.	*/
	if(g_server){
		sntVerbosePrintf("Creating server socket.\n");
		if(sntInitServer(port, &conopt) == 0){
			return EXIT_FAILURE;
		}
		sntServerMain();
	}

	/*	Create client.	*/
	if(g_client){
		sntVerbosePrintf("Creating client socket.\n");
		if(sntInitClient(g_numcliconne) == 0){
			fprintf(stderr, "Failed to connect to %s:%d.\n", host, port);
			return EXIT_FAILURE;
		}
		sntClientMain(host, port, g_numcliconne, &conopt);
	}

	return EXIT_SUCCESS;
}
