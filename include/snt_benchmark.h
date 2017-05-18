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
#ifndef _SNT_BENCHMARK_H_
#define _SNT_BENCHMARK_H_ 1
#include <snt_protocol.h>
#include"snt_time.h"

typedef struct snt_connection_t SNTConnection;

/**
 *	Benchmark protocol mode between server and client.
 */
#define SNT_PROTOCOL_BM_MODE_UNKNOWN		0x0		/*	Unknown protocol mode.	*/
#define SNT_PROTOCOL_BM_MODE_PERFORMANCE	0x1		/*	Benchmark network performance.	*/
#define SNT_PROTOCOL_BM_MODE_INTEGRITY		0x2		/*	Performance network integrity check.	*/
#define SNT_PROTOCOL_BM_MODE_FILE			0x4		/*	Not supported.	*/
#define SNT_PROTOCOL_BM_MODE_ALL 												\
		(SNT_PROTOCOL_BM_MODE_PERFORMANCE | SNT_PROTOCOL_BM_MODE_INTEGRITY |	\
		SNT_PROTOCOL_BM_MODE_FILE)												\

extern const char* gc_bench_symbol[];

/**
 *	Create benchmark thread.
 *
 *	@Return none 0 if successfully.
 */
extern pthread_t sntCreateBenchmarkThread(unsigned int mode,
		SNTConnection* patt);

/**
 *	Wait in till client sends start packet.
 *
 *	@Return non zero if disconnected.
 */
extern int sntWaitBenchmark(SNTConnection* connection);

/**/
extern void sntWaitFrequency(SNTConnection* connection);

/**
 *	Send packet diagram with ID string.
 */
extern void* sntClientIntegrityBenchmark(void* patt);

/**
 *	Sends full MTU data diagram
 *	data it can handle between client and server.
 */
extern void* sntClientPerformanceBenchmark(void* patt);

/**
 *	Sending file as benchmark.
 *	Used as a way to create a
 *	reproductive result.
 */
extern void* sntClientFileBenchmark(void* patt);

#endif
