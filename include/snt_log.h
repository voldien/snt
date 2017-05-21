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
#include"snt.h"

/**
 *	verbosity levels.
 */
#define SNT_LOG_QUITE	0x0
#define SNT_LOG_VERBOSE	0x1
#define SNT_LOG_DEBUG	0x3

/**
 *
 */
extern void sntVerbosityLevelSet(unsigned int verbosity);

/**
 *
 */
extern int sntLogPrintfInternal(unsigned int verbosity, const char* fmt,...);


/**
 *
 */
#define sntDebugPrintf(fmt,...)		\
	sntLogPrintfInternal(SNT_LOG_DEBUG, fmt, ## __VA_ARGS__)
#define sntVerbosePrintf(fmt,...)	\
	sntLogPrintfInternal(SNT_LOG_VERBOSE, fmt, ## __VA_ARGS__)
#define sntLogPrintf(verbosity, fmt, args...) sntLogPrintfInternal(verbosity, fmt, args);		\


#endif