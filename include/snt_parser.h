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
#ifndef _SNT_PARSER_H_
#define _SNT_PARSER_H_ 1
#include"snt_def.h"


/**
 *	Parse bit flag argument options. Where each
 *	argument is separated by comma. Where all and none
 *	are reserved key word.
 *
 *	\arg
 *
 *	\opts array of option null terminated string.
 *
 *	@Return bitwise option.
 */
extern unsigned int sntParserBitWiseMultiParam(const char* __restrict__ arg,
		const char** __restrict__ opts);


#endif
