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
#ifndef _SNT_PROTOCOL_FUNC_H_
#define _SNT_PROTOCOL_FUNC_H_ 1
#include "snt_protocol.h"

/**
 *	Protocol command functions.
 */
extern int sntProtFuncInit(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncCliOpt(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncCertificate(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncSecure(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncReady(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncStart(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncError(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncResult(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);
extern int sntProtFuncBenchmark(SNTConnection* __restrict__ connection,
		const SNTUniformPacket* __restrict__ packet);

/**
 *	Validate capability of system.
 *
 *	@Return 0 if successfully.
 */
extern int sntValidateCapability(const SNTClientOption* option);

/**
 *	Send certificate to client.
 *
 *	@Return none zero if successful.
 */
extern int sntSendCertificate(const SNTConnection* __restrict__ bind,
		SNTConnection* __restrict__ client);
/**
 *	Send error code.
 *
 *	@Return number of bytes sent.
 */
extern int sntSendError(const SNTConnection* __restrict__ connection,
		int code, const char* __restrict__ message);
/**
 *
 *	@Return number of bytes sent.
 */
extern int sntSendBenchMarkResult(const SNTConnection* connection, const SNTResultPacket* result);

#endif
