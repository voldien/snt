/**
    Simple network benchmark tool.
    Copyright (C) 2017  Valdemar Lindberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef _SNT_H_
#define _SNT_H_ 1
#include "snt_def.h"
#include "snt_pool.h"
#include "snt_delta.h"

/**
 *	Forward data type declaration.
 */
typedef struct snt_connection_t SNTConnection;

/**
 *	Global data.
 */
extern unsigned int g_verbosity;        /*	Verbosity level.	*/
extern unsigned int g_server;           /*	Server mode.	*/
extern unsigned int g_client;           /*	Client mode.	*/
extern SNTPool* g_connectionpool;       /*	connection pool. (Used by the server only)	*/
extern SNTConnection* g_bindconnection; /*	Connection used for binding socket to program. (Server only).	*/
extern void* g_threadtable;             /*	Thread table for each connection.	(Server only)	*/
extern SNTConnection** g_contable;      /*	Maps file descriptor to connection.	*/
extern int g_numcliconne;               /*	Number of client connection. (Client only).	*/
extern char* g_filepath;                /*	File for file benchmark mode.	*/
extern char* g_cerficatefilepath;       /*	Certificate file path.	*/
extern char* g_prikeyfilepath;          /*	Private key file.	*/
extern char* g_dhfilepath;              /*	Diffie hellman certificate file.    */

/**
 *	Connection option.
 */
typedef struct snt_connection_option_t{
	int32_t affamily;           /*	Address family.	*/
	uint32_t ssl;               /*	Use secure connection via SSL.	*/
	uint32_t useCert;			/*	*/
	uint32_t useDHfile;			/*	*/
	uint32_t compression;       /*	Compression.	*/
	uint32_t bm_protocol_mode;  /*	Benchmark mode.	*/
	uint32_t transport_mode;    /*	Transport layer protocol.	*/
	uint32_t symmetric;         /*	Symmetric cipher.	*/
	uint32_t asymmetric;        /*	Asymmetric cipher.	*/
	uint32_t asymmetric_bits;   /*	Asymmetric cipher key bitsize.	*/
	uint32_t hash;              /*	Hash algorithm.	*/
	uint32_t deltatype;         /*	Delta type.	*/
	SNTDelta delta;             /*	Incremental delta.	*/
	uint64_t invfrequency;      /*	Frequency of number of packet sent per sec.	*/
	uint16_t payload;           /*	Size of payload.	*/
	int32_t listen;             /*	Number of listen. (Server only).	*/
	uint64_t duration;          /*	Duration in nano seconds.	*/
	uint32_t port;              /*	Port.	*/
	uint32_t certificate;       /*	Certficate.	*/
	uint32_t dh;                /*	Diffie hellman.	*/
	uint32_t duplex;            /*	Duplex.	*/
}SNTConnectionOption;

/**
 *	@Return non-null pointer.
 */
extern const char* sntGetVersion(void);

/**
 *	Read option arguments.
 */
extern void sntReadArgument(int argc,  char *const * __restrict__ argv,
		char* __restrict__ ip, unsigned int* __restrict__ port,
		SNTConnectionOption* __restrict__ option);

/**
 *	Initialize the program for running as a server.
 *
 *	@Return non zero if successfully.
 */
extern int sntInitServer(unsigned int port, SNTConnectionOption* option);

/**
 *	Initialize the program for running as a client.
 *
 *	@Return non zero if successfully.
 */
extern int sntInitClient(unsigned int nparallcon);

/**
 *	Server main loop. Will run indefinitely.
 */
extern void sntServerMain(void);

/**
 *	Client main loop.
 */
extern void sntClientMain(const char* __restrict__ host, unsigned int port,
		int nconnector, const SNTConnectionOption* __restrict__ option);

/**
 *	Interpret incoming packets.
 *
 *	@Return number of bytes total received data.
 */
extern int sntPacketInterpreter(SNTConnection* connection);

#endif
