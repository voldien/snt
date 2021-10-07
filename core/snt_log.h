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
#ifndef _SNT_LOG_H_
#define _SNT_LOG_H_ 1
#include "snt.h"

/**
 *	Verbosity levels.
 */
#define SNT_LOG_QUITE 0x0	/*	Will oppress all print out on the sntLogPrintfInternal function.	*/
#define SNT_LOG_VERBOSE 0x1 /*	Print only verbose print outs.	*/
#define SNT_LOG_DEBUG 0x3	/*	Prints everything.	*/
enum SntLogVerbosity {
	SntVerbosityQuite,
	SntVerbosityInfo,
	SntVerbosityDebug,
	SntVerbosityWarning,
	SntVerbosityError,
};

typedef struct snt_logger_t {
	enum SntLogVerbosity verbosity;
} Logger;

extern void createLogger(Logger *logger);

extern void sntLogPrint(Logger *logger, unsigned int verbosity, const char *message);
extern void sntLogPrintf(Logger *logger, unsigned int verbosity, const char *fmtMessage, ...);
extern void sntVerbosityLevelSet(Logger *logger, unsigned int verbosity);

extern void sntLogInfoPrintf(Logger *logger);
extern void sntLogErrorPrintf(Logger *logger);
extern void sntLogWarningPrintf(Logger *logger);

/**
 *	Set verbosity level.
 */
extern void sntVerbosityLevelSet(unsigned int verbosity);

/**
 *	Set syslog state. Default disabled.
 */
extern void sntLogEnableSys(unsigned int enable);

/**
 *	Log.
 *
 *	@Return number of bytes.
 */
extern int sntLogPrintfInternal(unsigned int verbosity, const char *fmt, ...);

/**
 *	Print error.
 *
 *	@Return number of bytes.
 */
extern int sntLogErrorPrintf(const char *fmt, ...);

/**
 *	Print.
 */
#define sntDebugPrintf(fmt, args...) sntLogPrintfInternal(SNT_LOG_DEBUG, fmt, ##args)
#define sntVerbosePrintf(fmt, args...) sntLogPrintfInternal(SNT_LOG_VERBOSE, fmt, ##args)
#define sntLogPrintf(verbosity, fmt, args...) sntLogPrintfInternal(verbosity, fmt, args)

#endif
