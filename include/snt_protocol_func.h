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
extern int sntProtFuncInit(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncCliOpt(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncCertificate(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncSecure(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncReady(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncStart(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncError(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncResult(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncBenchmark(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncDHReq(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncDHInit(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);
extern int sntProtFuncDHExch(SNTConnection* SNT_RESTRICT connection,
		const SNTUniformPacket* SNT_RESTRICT packet);

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
extern int sntSendCertificate(const SNTConnection* SNT_RESTRICT bind,
		SNTConnection* SNT_RESTRICT client);

/**
 *	Send Diffie hellman request.
 *
 *	@Return number of bytes sent.
 */
extern int sntSendDHpq(const SNTConnection* SNT_RESTRICT bind,
		SNTConnection* SNT_RESTRICT client);

/**
 *	Send Diffie hellman exchange packet.
 *
 *	@Return number of bytes sent.
 */
extern int sntSendDHExch(const SNTConnection* SNT_RESTRICT connection);

/**
 *	Send ready packet to connection.
 *
 *	@Return number of bytes sent.
 */
extern int sntSendReady(const SNTConnection* SNT_RESTRICT connection);

/**
 *	Send error code.
 *
 *	@Return number of bytes sent.
 */
extern int sntSendError(const SNTConnection* SNT_RESTRICT connection,
		int code, const char* SNT_RESTRICT message);
/**
 *
 *	@Return number of bytes sent.
 */
extern int sntSendBenchMarkResult(const SNTConnection* connection, const SNTResultPacket* result);

#endif
