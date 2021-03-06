#include "snt.h"
#include "snt_utility.h"
#include "snt_debug.h"
#include "snt_protocol.h"
#include "snt_protocol_func.h"
#include "snt_schd.h"
#include "snt_parser.h"
#include "snt_benchmark.h"
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>

unsigned int g_verbosity = SNT_LOG_QUITE;
unsigned int g_server = 0;
unsigned int g_client = 1;
SNTPool* g_connectionpool = NULL;
SNTConnection* g_bindconnection = NULL;
void* g_threadtable = NULL;
SNTConnection** g_contable = NULL;
unsigned int g_curthread = 0;
int g_numcliconne = 1;
char* g_filepath = NULL;
char* g_cerficatefilepath = "/etc/ssl/certs/snt.cert";
char* g_prikeyfilepath = "~/.snt/snt.pem";
char* g_dhfilepath = "/etc/ssl/certs/sntdh.pem";

const char* sntGetVersion(void){
	return SNT_STR_VERSION " (" SNT_ARCH ") -- " SNT_COMPILER_NAME;
}

static void snt_default_con_option(SNTConnectionOption* option, unsigned int isServer){

	option->affamily = AF_INET;
	option->ssl = 0;
	option->useCert = 0;
	option->useDHfile = 0;
	option->compression = 0;
	option->symmetric = SNT_ENCRYPTION_AES_ECB128;
	option->asymmetric = SNT_ENCRYPTION_ASYM_RSA;
	option->asymmetric_bits = 1024;
	option->hash = SNT_HASH_SHA256;
	option->delta.i = 1;
	option->invfrequency = 0;
	option->payload = 1500;
	option->listen = 128;
	option->duration = (uint64_t)(10 * sntGetTimeResolution());
	option->port = SNT_DEFAULT_PORT;
	option->certificate = SNT_CERTIFICATE_RSA;
	option->duplex = SNT_DUPLEX_SIMPLE;

	if(isServer){
		option->bm_protocol_mode = SNT_PROTOCOL_BM_MODE_ALL;
		option->transport_mode = SNT_TRANSPORT_ALL;
		option->deltatype = SNT_DELTA_TYPE_ALL;
		option->dh = 1024;
	}
	else{
		option->bm_protocol_mode = SNT_PROTOCOL_BM_MODE_PERFORMANCE;
		option->transport_mode = SNT_TRANSPORT_TCP;
		option->deltatype = SNT_DELTA_TYPE_INT;
		option->dh = 1;
	}
}

void sntReadArgument(int argc,  char *const * argv, char* ip, unsigned int* port,
		SNTConnectionOption* option) {

	unsigned int i;
	int c;
	const char* shortopt = "vVD46ySCUTh:b:p:s:c:P:n:B:f:H:F:m:d:r:A:X:x:";

	static struct option longoption[] = {
		{"version",         no_argument,        NULL, 'v'}, /*	Print out version.	*/
		{"verbose",         no_argument,        NULL, 'V'}, /*	Enable verbose.	*/
		{"debug",           no_argument,        NULL, 'D'}, /*	Enable debug.	*/
		{"quite",           no_argument,        NULL, 'q'}, /*	Enable debug.	*/
		{"ipv4",            no_argument,        NULL, '6'}, /*	Use IPv4.	*/
		{"ipv6",            no_argument,        NULL, '4'}, /*	Use IPv6 mode.	*/
		{"syslog",          no_argument,        NULL, 'y'}, /*	Syslog.	*/
		{"udp",             no_argument,        NULL, 'U'}, /*	UDP protocol for transfer. TCP will be used for exchanging keys.	*/
		{"tcp",             no_argument,        NULL, 'T'}, /*	TCP protocol for transfer.	*/
		{"payload",         required_argument,  NULL, 'm'}, /*	payload.	*/
		{"frequency",       required_argument,  NULL, 'F'}, /*	frequency.	*/
		{"delta",           required_argument,  NULL, 'd'}, /*	Delta type.	*/
		{"duration",        required_argument,  NULL, 'r'}, /*	Duration.	*/
		{"duplex",          required_argument,  NULL, 'M'}, /*	Duplex.	*/
		{"compression",     optional_argument,  NULL, 'C'}, /*	Use compression.	*/
		{"secure",          optional_argument,  NULL, 'S'}, /*	Use secure connection.	*/
		{"server",          optional_argument,  NULL, 's'}, /*	Server mode.	*/
		{"hash",            required_argument,  NULL, 'H'}, /*	Use secure connection.	*/
		{"host",            required_argument,  NULL, 'h'}, /*	Host to connect too.	*/
		{"port",            required_argument,  NULL, 'p'}, /*	Port to connect via too.*/
		{"transport",       required_argument,  NULL, 't'}, /*	Transport layer.	*/
		{"listen",          required_argument,  NULL, 'l'}, /*	Number TCP listen	*/
		{"parallel",        required_argument,  NULL, 'n'}, /*	Parallel connections. (Not supported.)	*/
		{"benchmarkmode",   required_argument,  NULL, 'b'}, /*	benchmark mode.	*/
		{"cipher",          required_argument,  NULL, 'c'}, /*	Cipher mode.	*/
		{"public-key",      required_argument,  NULL, 'P'}, /*	Public cipher used for exchanging symmetric key.	*/
		{"public-nbits",    required_argument,  NULL, 'B'}, /*	Number of bits used for public cipher.	*/
		{"file",            required_argument,  NULL, 'f'}, /*	File to be transfered.	*/
		{"affinity",        required_argument,  NULL, 'A'}, /*	Affinity mapping, -A, --affinity n/n,m 	*/
		{"certificate",     required_argument,  NULL, 'X'}, /*	Certificate.	*/
		{"private-key",     required_argument,  NULL, 'x'}, /*	Private key.	*/
		{"dh",              optional_argument,  NULL, 'i'}, /*	Diffie hellman parameter.	*/
		{NULL, 0, NULL, 0}
	};

	/*	First pass.	*/
	while ((c = getopt_long(argc, (char * const *) argv, shortopt, longoption,
			NULL)) != EOF) {
		switch(c){
		case 'v':
			printf("version %s.\n", sntGetVersion());
			exit(EXIT_SUCCESS);
			break;
		case 'V':
			sntVerbosityLevelSet(SNT_LOG_VERBOSE);
			break;
		case 'D':
			sntVerbosityLevelSet(SNT_LOG_DEBUG);
			break;
		case 'q':
			sntVerbosityLevelSet(SNT_LOG_QUITE);
			break;
		case 'y':
			if(g_server){
				sntLogEnableSys(1);
			}else{
				sntLogErrorPrintf("Requires to run as server in order to use syslog.\n");
			}
			break;
		case 's':
			g_server = 1;
			g_client = 0;
			break;
		default:
			break;
		}
	}

	/*	Default connection options.	*/
	snt_default_con_option(option, g_server);

	/*	Reset getopt.	*/
	opterr = 0;
	optind = 0;
	optopt = 0;
	optarg = NULL;

	/*	Second pass.	*/
	while( (c = getopt_long(argc, (char *const *)argv, shortopt, longoption, NULL) ) != EOF){
		switch(c){
		case '4':	/*	Use AF_INET.	*/
			sntVerbosePrintf("Address family set to IPv4.\n");
			option->affamily = AF_INET;
			break;
		case '6':	/*	Use AF_INET6.	*/
			sntVerbosePrintf("Address family set to IPv6.\n");
			option->affamily = AF_INET6;
			break;
		case 'b':	/*	benchmark mode.	*/
			if(optarg){
				option->bm_protocol_mode = sntParserBitWiseMultiParam(optarg, gc_bench_symbol);
				sntVerbosePrintf("Using %s for benchmark mode .\n", optarg);
			}
			break;
		case 'C':	/*	Use compression.	*/
			if(optarg){
				option->compression = sntParserBitWiseMultiParam(optarg, gs_symcompression);
				sntVerbosePrintf("Using %s for compression.\n", optarg);
				sntInitCompression(option->compression);
			}
			break;
		case 'p':	/*	Port.	*/
			if(optarg && port){
				*port = (unsigned int)strtoll(optarg, NULL, 10);
				sntVerbosePrintf("port set to %d.\n", *port);
			}
			break;
		case 'h':	/*	Host.	*/
			if(optarg && ip){
				memcpy(ip, optarg, strlen(optarg) + 1);
				ip[strlen(optarg)] = '\0';
				sntVerbosePrintf("host address set to :%s\n", ip);
			}
			break;
		case 'S':	/*	Secure connection.	*/
			option->ssl = 1;
			break;
		case 'H':
			if(optarg){
				i = 0;
				do{
					if(strcmp(gc_hash_symbol[i], optarg) == 0){
						break;
					}
					i++;
					if(gc_hash_symbol[i] == NULL){
						sntLogErrorPrintf("Invalid hash algorithm, %s.\n", optarg);
						exit(EXIT_FAILURE);
					}
				}while(gc_hash_symbol[i]);

				option->hash = i;
				sntVerbosePrintf("Using %s for digital signature.\n", gc_hash_symbol[i]);
			}
			break;
		case 'F':
			if(optarg && option){
				double timefraction;
				double dummyfraction;

				timefraction = strtod(optarg, NULL);
				if( modf(timefraction, &dummyfraction) == 0.0){
					/*	*/
					option->invfrequency = (uint64_t)strtol(optarg, NULL, 10);
					option->invfrequency = (uint64_t)sntGetTimeResolution() / option->invfrequency;
					sntVerbosePrintf("frequency set to :%ld hz\n", sntGetTimeResolution() / option->invfrequency);
				}else{
					/*	*/
					option->invfrequency = (uint64_t)((float)sntGetTimeResolution() / timefraction);
					sntVerbosePrintf("frequency set to :%f hz\n", (float)sntGetTimeResolution() / (float)option->invfrequency);
				}
			}
			break;
		case 't':	/*	Transport protocol.	*/
			if(optarg && option){
				option->transport_mode = sntParserBitWiseMultiParam(optarg, gs_sym_transport);
				sntVerbosePrintf("Using %s for transport layer.\n", optarg);
			}
			break;
		case 'd':
			if(optarg && option){
				option->deltatype = sntParserBitWiseMultiParam(optarg, gs_delta_sym);
				sntVerbosePrintf("Using %s for as delta type.\n", optarg);
			}
			break;
		case 'r':
			if(optarg){
				option->duration = (uint64_t)(strtod(optarg, NULL) * (double)sntGetTimeResolution());
				sntVerbosePrintf("Duration time set to : %ld.\n", (long int)option->duration / sntGetTimeResolution() );
			}
			break;
		case 'M':
			if(optarg){
				option->duplex = sntParserBitWiseMultiParam(optarg, gs_sym_duplex);
				sntVerbosePrintf("Using %s duplex.\n", optarg);
				sntLogErrorPrintf("Duplex mode not supported, option will be ignored.\n");
			}
			break;
		case 'U':	/*	Use UDP transport protocol.	*/
			option->transport_mode = SNT_TRANSPORT_UDP;
			sntVerbosePrintf("UDP.\n");
			break;
		case 'T':	/*	Use TCP transport protocol.	*/
			option->transport_mode = SNT_TRANSPORT_TCP;
			sntVerbosePrintf("TCP.\n");
			break;
		case 'm':
			if(optarg && option){
				option->payload = (uint16_t)strtol(optarg, NULL, 10);
				sntVerbosePrintf("Payload set to %d.\n", option->payload);
			}
			break;
		case 'n':
			if(optarg){
				g_numcliconne = (int)strtol(optarg, NULL, 10);
				sntVerbosePrintf("Number of parallel connection set to %d.\n", g_numcliconne);
			}
			break;
		case 'l':
			if(optarg && option){
				option->listen = (int)strtol(optarg, NULL, 10);
			}
			break;
		case 's':
			if(optarg){
				/*	Bind addresses.	*/
				strcpy(ip, optarg);
			}
			g_client = 0;
			g_server = 1;
			break;
		case 'c':
			if(optarg){
				option->symmetric = sntParserBitWiseMultiParam(optarg, gc_symchi_symbol);
				sntVerbosePrintf("Using %s for symmetric cipher .\n", optarg);
			}
			break;
		case 'P':	/*	Asymmetric cipher.	*/
			if(optarg){
				option->asymmetric = sntParserBitWiseMultiParam(optarg, gc_asymchi_symbol);
				sntVerbosePrintf("Using %s for asymmetric cipher .\n", optarg);
			}
			break;
		case 'B':	/*	Number of bits.	*/
			if(optarg){
				option->asymmetric_bits = (unsigned int)strtol(optarg, NULL, 10);
				if(option->asymmetric_bits <= 0){
					sntLogErrorPrintf("Invalid asymmetric bit size, %s.\n", optarg);
					exit(EXIT_FAILURE);
				}
			}
			break;
		case 'f':	/*	File.	*/
			if(optarg){
				sntDebugPrintf("Verifying the file %s exists.\n", optarg);
				g_filepath = optarg;
				if(access(g_filepath, F_OK | R_OK) != 0){
					sntLogErrorPrintf("File %s is not accessible, %s.\n", optarg, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
			break;
		case 'A':
			if(optarg){
				unsigned int cpu,core,size;
				/*	parse input.	*/
				sscanf(optarg, "%d,%d,%d", &cpu, &core, &size);
				sntVerbosePrintf("Affinity.\n");
				sntSchdSetAffinity(cpu, core, size);
			}
			break;
		case 'X':
			if(optarg){
				/*	Use certificate file.	*/
				sntDebugPrintf("Verifying the file %s exists.\n", optarg);
				g_cerficatefilepath = optarg;
				if(access(g_cerficatefilepath, F_OK | R_OK) != 0){
					sntLogErrorPrintf("File %s is not accessible, %s.\n", optarg, strerror(errno));
					exit(EXIT_FAILURE);
				}
				option->certificate = SNT_CERTIFICATE_X509;
			}
			break;
		case 'x':
			if(optarg){
				sntDebugPrintf("Verifying the file %s existing.\n", optarg);
				g_prikeyfilepath = optarg;
				if(access(g_prikeyfilepath, F_OK | R_OK) != 0){
					sntLogErrorPrintf("File %s is not accessible, %s.\n", optarg, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
			break;
		case 'i':
			if(optarg){
				if(access(optarg, F_OK | R_OK) != 0){
					g_dhfilepath = optarg;
				}else{
					option->dh = (uint32_t)strtol(optarg, NULL, 10);
					g_dhfilepath = NULL;
					sntVerbosePrintf("Diffie hellman set to %d bit.\n", option->dh);
				}
			}else{
				option->dh = 1;
			}
			break;
		default:
			break;
		}
	}

	if(optind > 0 && !g_server){
		if(optarg){
			memcpy(ip, optarg, strlen(optarg) + 1);
			sntVerbosePrintf("%s.\n", optarg);
		}
		g_client = 1;
		g_server = 0;
	}

	/*	Reset getopt.	*/
	opterr = 0;
	optind = 0;
	optopt = 0;
	optarg = NULL;
}

static void sntMapSocket(SNTConnection** table, SNTConnection* __restrict__ con,
		fd_set* __restrict__ fdset, int socket) {
	if(socket > 0){
		FD_SET(socket, fdset);
		table[socket] = con;
	}
}

static void sntUnMapSocket(SNTConnection** __restrict__ table,
		fd_set* __restrict__ fdset, int socket) {
	if(socket > 0){
		FD_CLR(socket, fdset);
		table[socket] = NULL;
	}
}

void sntServerMain(void){

	SNTConnection* con = NULL;	/*	*/
	volatile int fd_size = 0;	/*	*/
	fd_set fd_read;				/*	*/
	fd_set fd_active;			/*	*/

	int ret;					/*	*/
	int i;						/*	*/

	/*	*/
	FD_ZERO(&fd_active);
	FD_ZERO(&fd_read);

	/*	*/
	FD_SET(g_bindconnection->tcpsock, &fd_active);
	fd_size = g_bindconnection->tcpsock + 1;

	/*	*/
	while(1){
		fd_read = fd_active;

		/*	Wait for incoming packets.	*/
		ret = select(fd_size, &fd_read, NULL, NULL, NULL);
		if (ret < 0 ){
			perror("Failed select.\n");
			exit(EXIT_FAILURE);
		}
		else{
			/*	Iterate through each file descriptor.	*/
			for (i = 2; i < fd_size; i++){
				if (FD_ISSET (i, &fd_read)){

					/*	Check for incoming connection.	*/
					if(i == g_bindconnection->tcpsock){
						con = sntAcceptSocket(g_bindconnection);
						if(con == NULL){
							sntLogErrorPrintf("Failed to accept connection.\n");
							continue;
						}
						/*	Map connection to socket table.	*/
						sntMapSocket(g_contable, con, &fd_active, con->tcpsock);
						sntMapSocket(g_contable, con, &fd_active, con->udpsock);

						/*	Add socket file descriptor to select IO blocking.	*/
						fd_size = sntMax(fd_size, con->tcpsock + 1);
						fd_size = sntMax(fd_size, con->udpsock + 1);
					}
					else{
						/*	Get connection pointer.*/
						con = g_contable[i];
						assert(con);

						/*	Read incoming packets.	*/
						if(sntPacketInterpreter(con) <= 0){
							/*	Unmap from IO select blocking.	*/
							sntUnMapSocket(g_contable, &fd_active, con->udpsock);
							sntUnMapSocket(g_contable, &fd_active, con->tcpsock);

							con->flag &= ~(SNT_CONNECTION_BENCH);
							sntDisconnectSocket(con);
							continue;
						}

						/*	Create benchmark thread.	*/
						if( (sntIsBenchEnable(con)) ){

							if(con->option->transport_mode & SNT_TRANSPORT_UDP) {
								sntUnMapSocket(g_contable, &fd_active, con->udpsock);
							}else if(con->option->transport_mode & SNT_TRANSPORT_TCP) {
								sntUnMapSocket(g_contable, &fd_active, con->tcpsock);
							}else {
								assert(0);
							}
							/*	*/
							((pthread_t*)g_threadtable)[sntPoolGetIndex(g_connectionpool, con)] =
									sntBenchmarkCreateThread(con->option->bm_protocol_mode,
											con);
						}

					}
				}

			}/*	program client/server.	*/
		}/*	Select end.*/
	}
}

void sntClientMain(const char* host, unsigned int port, int nconnector, const SNTConnectionOption* option){

	/*	*/
	int i;
	int ret;
	volatile int fd_size = 1;			/*	*/
	fd_set fd_read;						/*	*/
	fd_set fd_active;					/*	*/
	SNTConnection* con;
	volatile int numalive = nconnector;

	/*	*/
	FD_ZERO(&fd_active);
	FD_ZERO(&fd_read);

	/*	Connecting to server.	*/
	assert(nconnector > 0);
	for(i = 0; i < nconnector; i++){
		con = sntConnectSocket(host, (uint16_t)port, option);
		if(con == NULL){
			return;
		}

		/*	Add connection to hash table with file descriptor as key.	*/
		sntMapSocket(g_contable, con, &fd_active, con->tcpsock);
		fd_size = sntMax(fd_size, con->tcpsock + 1);

		/*	Add UDP socket to hash table if created.	*/
		if(con->udpsock > 0){
			sntMapSocket(g_contable, con, &fd_active, con->udpsock);
			fd_size = sntMax(fd_size, con->udpsock + 1);
		}
	}

	/*	Main loop.	*/
	while(numalive > 0){
		fd_read = fd_active;

		/*	*/
		ret = select(fd_size, &fd_read, NULL, NULL, NULL);
		if (ret < 0 ){
			perror("Failed select.\n");
			exit(EXIT_FAILURE);
		}
		/*	Iterate throug each client file descriptor.	*/
		for(i = 2; i < fd_size; i++){
			if(FD_ISSET(i, &fd_read)){
				con = g_contable[i];

				/*	interpret.	*/
				if(sntPacketInterpreter(con) <= 0){
					numalive--;
					sntUnMapSocket(g_contable, &fd_active, con->tcpsock);
					if(con->udpsock > 0){
						sntUnMapSocket(g_contable, &fd_active, con->udpsock);
					}
					sntDisconnectSocket(con);
					continue;
				}
			}
		}/*	for*/
	}/*	While(1)*/
}


int sntInitServer(unsigned int port, SNTConnectionOption* option){

	unsigned int poolsize;

	/*	*/
	poolsize = (unsigned int)option->listen;
	sntVerbosePrintf(
			"Creating connection pool %d connections, size %d bytes.\n",
			option->listen, sizeof(SNTConnection) * option->listen);
	g_connectionpool = (SNTPool*)sntPoolCreate(poolsize, sizeof(SNTConnection));
	if(g_connectionpool == NULL){
		sntLogErrorPrintf("Failed to allocate connection pool.\n");
		return 0;
	}

	/*	Prevent sensitive information from being swapped to disk.	*/
	if(!sntPoolLockMem(g_connectionpool)){
		return 0;
	}

	/*	Allocate connection hash table.	*/
	sntVerbosePrintf("Allocating %d connections, size %d bytes.\n", poolsize,
			sizeof(SNTConnection*) * option->listen);
	g_contable = (SNTConnection**)malloc(FD_SETSIZE * sizeof(SNTConnection**));
	if( g_contable == NULL){
		sntLogErrorPrintf("Failed to allocate connection hash mapping table.\n");
		return 0;
	}
	memset(g_contable, 0, FD_SETSIZE * sizeof(pthread_t));

	/*	Allocate thread hash pool.	*/
	g_threadtable = (pthread_t*)malloc(poolsize * sizeof(pthread_t));
	if( g_contable == NULL){
		sntLogErrorPrintf("Failed to allocate connection hash mapping table.\n");
		return 0;
	}
	memset(g_threadtable, 0, poolsize * sizeof(pthread_t));

	/*	Bind socket to process.	*/
	g_bindconnection = sntBindSocket("0.0.0.0",(uint16_t)port, option);
	if(g_bindconnection == NULL){
		return 0;
	}

	/*	Check if encryption is enabled.	*/
	if(option->ssl){

		if(g_cerficatefilepath && option->useCert){

			/*	Create public key from x509 certificate.	*/
			sntVerbosePrintf("Started loading x509 certificate : %s \n",
					g_cerficatefilepath);
			if(!sntASymCreateFromX509File(g_bindconnection, g_cerficatefilepath)){
				sntLogErrorPrintf("Failed, X509 not supported.\n");
				sntDisconnectSocket(g_bindconnection);
				return 0;
			}

			/*	*/
			sntVerbosePrintf("Started loading private key : %s \n", g_prikeyfilepath);
			if(!sntASymCreateKeyFromFile(g_bindconnection, g_bindconnection->asymchiper, g_prikeyfilepath, 1)){
				sntLogErrorPrintf("sntASymCreateKeyFromFile Failed.\n");
				sntDisconnectSocket(g_bindconnection);
				return 0;
			}
		}else{
			sntVerbosePrintf("Started generating asymmetric key, %s : %d.\n",
					gc_asymchi_symbol[sntLog2MutExlusive32(option->asymmetric)], option->asymmetric_bits);
			/*	Create asymmetric key and check if successfully.	*/
			if(sntASymGenerateKey(g_bindconnection, option->asymmetric, option->asymmetric_bits) == 0){
				sntLogErrorPrintf("Failed to create asymmetric cipher key.\n");
				sntDisconnectSocket(g_bindconnection);
				return 0;
			}
		}

		/*  Check if diffie hellman option selected.    */
		if(option->dh > 0){
			/*  Check if to load from file. */
			if(g_dhfilepath && option->useCert){
				/*	Create Diffie hellman from file.	*/
				sntVerbosePrintf("Loading Diffie hellman from file %s.\n", g_dhfilepath);
				if(!sntDHCreateFromPEMFile(&g_bindconnection->dh, g_dhfilepath)){
					sntLogErrorPrintf("Failed to load diffie hellman, %s.\n", g_dhfilepath);
					sntDisconnectSocket(g_bindconnection);
					return 0;
				}
			}else{
				/*	Generate Diffie hellman.	*/
				sntVerbosePrintf("Creating Diffie hellman %d bit.\n", option->dh);
				if (!sntDHCreate(&g_bindconnection->dh, option->dh)) {
					sntLogErrorPrintf("Failed to create diffie hellman.\n");
					sntDisconnectSocket(g_bindconnection);
					return 0;
				}
			}
		}
	}

	return 1;
}

int sntInitClient(unsigned int nparallcon){

	nparallcon += 1;

	sntVerbosePrintf("Creating connection pool %d connections, size %d.\n",
			nparallcon, sizeof(SNTConnection) * nparallcon);
	g_connectionpool = (SNTPool*)sntPoolCreate(nparallcon, sizeof(SNTConnection));
	if(g_connectionpool == NULL){
		sntLogErrorPrintf("Failed to allocate connection pool.\n");
		return 0;
	}

	/*	Prevent sensitive information from being swapped to disk.	*/
	sntPoolLockMem(g_connectionpool);

	/*	Allocate connection lookup table.	*/
	g_contable = (SNTConnection**)calloc(FD_SETSIZE, sizeof(SNTConnection*));
	assert(g_contable);

	return 1;
}

int sntPacketInterpreter(SNTConnection* connection){

	int len;
	SNTUniformPacket* packbuf = (SNTUniformPacket*)connection->mtubuf;

	assert(packbuf);

	/*	Fetch incoming packet.	*/
	len = sntReadSocketPacket(connection, packbuf);
	if(len <= 0){
		return 0;
	}

	/*	Protocol command.	*/
	switch(sntProtocolPacketCommand(&packbuf->header)){
	case SNT_PROTOCOL_STYPE_INIT:
		return sntProtFuncInit(connection, packbuf);
	case SNT_PROTOCOL_STYPE_CLIENTOPT:
		return sntProtFuncCliOpt(connection, packbuf);
	case SNT_PROTOCOL_STYPE_CERTIFICATE:
		return sntProtFuncCertificate(connection, packbuf);
	case SNT_PROTOCOL_STYPE_SECURE:
		return sntProtFuncSecure(connection, packbuf);
	case SNT_PROTOCOL_STYPE_READY:
		return sntProtFuncReady(connection, packbuf);
	case SNT_PROTOCOL_STYPE_ERROR:
		sntProtFuncError(connection, packbuf);
		return g_client ? 0 : 1;	/*	Prevent client to terminate the server.	*/
	case SNT_PROTOCOL_STYPE_BENCHMARK:
		return sntProtFuncBenchmark(connection, packbuf);
	case SNT_PROTOCOL_STYPE_RESULT:
		return sntProtFuncResult(connection, packbuf);
	case SNT_PROTOCOL_STYPE_STARTTEST:
		return sntProtFuncStart(connection, packbuf);
	case SNT_PROTOCOL_STYPE_DH_REQ:
		return sntProtFuncDHReq(connection, packbuf);
	case SNT_PROTOCOL_STYPE_DH_INIT:
		return sntProtFuncDHInit(connection, packbuf);
	case SNT_PROTOCOL_STYPE_DH_EXCH:
		return sntProtFuncDHExch(connection, packbuf);
	case SNT_PROTOCOL_STYPE_NONE:
	default:
		sntLogErrorPrintf("Undefined packet command type: %d.\n", packbuf->header.stype);
		sntSendError(connection, SNT_ERROR_BAD_REQUEST, "Invalid protocol command.\n");
		break;
	}

	return len;
}
