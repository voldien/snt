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
#ifndef _SNT_DELTA_H_
#define _SNT_DELTA_H_ 1
#include"snt_def.h"

/**
 *	Delta type.
 */
typedef union snt_delta_t{
	uint64_t i;		/*	Long int delta type.	*/
	float f;		/*	Float delta type.	*/
	double d;		/*	Double delta type.	*/
}SNTDelta;

/**
 *	Generate delta type text and post increment.
 *
 *	@Return number of bytes written to text.
 */
extern int sntGenerateDeltaTypeInc(unsigned int type, char* __restrict__ text,
		SNTDelta* __restrict__ delta, const SNTDelta* __restrict__ incr);

/**
 *	Parse delta binary.
 */
extern void sntDeltaParse(unsigned int type, const char* __restrict__ buf, SNTDelta* __restrict__ delta);

/**
 *	Check changed from previous delta and current delta.
 *
 *	@Return none zero if delta is correct from between prev and next.
 */
extern int sntDeltaCheckChange(unsigned int type, const SNTDelta* __restrict__ prev,
		const SNTDelta* __restrict__ next, const SNTDelta* __restrict__ incre);

/**
 *
 *	@Return number of bytes written.
 */
extern int sntGenerateAsciiFloat(char* text, float digit);

/**
 *	Convert string to float.
 *
 *	@Return
 */
extern float sntAsciiToFloat(const char* text);

/**
 *
 *	@Return number of bytes written.
 */
extern int sntGenerateAsciiDouble(char* text, double digit);

/**
 *	Convert string to double.
 *
 *	@Return
 */
extern double sntAsciiToDouble(const char* text);

/**
 *
 *	@Return number of bytes written.
 */
extern int sntGenerateAsciiLongInt(char* text, long int digit);

/**
 *	Convert string to long.
 *
 *	@Return
 */
extern long int sntAsciiToLongInt(const char* text);



#endif
