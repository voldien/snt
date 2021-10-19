#include "snt_benchmark.h"
#include "snt_debug.h"
#include "snt_log.h"
#include "snt_protocol.h"
#include "snt_schd.h"
#include "snt_utility.h"
#include <errno.h>
#include <signal.h>

static void snt_release() {

	unsigned int i;

	if (g_bindconnection) {
		sntDisconnectSocket(g_bindconnection);
		g_bindconnection = NULL;
	}
	/*	cleanup.	*/
	if (g_contable && g_connectionpool) {
		for (i = 0; i < FD_SETSIZE; i++) {
			if (g_contable[i] != NULL) {
				sntDisconnectSocket(g_contable[i]);
			}
		}
		free(g_contable);
		g_contable = NULL;
		free(g_threadtable);
		g_threadtable = NULL;
	}

	/*	Free connection pool.	*/
	if (g_connectionpool) {
		sntPoolFree(g_connectionpool);
		g_connectionpool = NULL;
	}

	/*	UnLock all memory.	*/
	sntMemoryUnLockAll();
}

/*	signal interrupts.	*/
void snt_catch(int signal) {

	/*	Ignore SIGPIPE.	*/
	if (signal == SIGPIPE)
		return;

	/*	*/
	sntDebugPrintf("Catch signal : %d.\n", signal);
	snt_release();
	exit(EXIT_SUCCESS);
}

class SntClient {
  private:
};
class SntServer {
  private:
};

int main(int argc, char *const *argv) {

	/*	*/
	SNTConnectionOption conopt;			  /*	*/
	char host[256] = {"127.0.0.1"};		  /*	*/
	unsigned int port = SNT_DEFAULT_PORT; /*	*/

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
	if (g_server) {

		/*	Lock memory.	*/
		sntMemoryLockAll();

		/*  Create server.  */
		sntVerbosePrintf("Creating server socket.\n");
		if (sntInitServer(port, &conopt) == 0) {
			return EXIT_FAILURE;
		}
		sntServerMain();
	}

	/*	Create client.	*/
	if (g_client) {
		sntVerbosePrintf("Creating client socket.\n");
		if (sntInitClient(g_numcliconne) == 0) {
			sntLogErrorPrintf("Failed to connect to %s:%d.\n", host, port);
			return EXIT_FAILURE;
		}
		sntClientMain(host, port, g_numcliconne, &conopt);
	}

	return EXIT_SUCCESS;
}
