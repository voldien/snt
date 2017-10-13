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
#ifndef _SNT_UTILITY_H_
#define _SNT_UTILITY_H_ 1
#include"snt_def.h"

/**
 *	Swap pointer value.
 */
extern void sntSwapPointer(void** __restrict__ a, void** __restrict__ b);

/**
 *	log2 with mutuality exclusive bit flag.
 *
 *	@Return exponent of base 2 for a.
 */
extern int sntLog2MutExlusive32(unsigned int a);

/**
 * 	Check if a is a power of 2.
 *
 *	@Return None zero if a is a power of two.
 */
extern int sntIsPower2(unsigned int a);

/**
 *	Return max value of a and b.
 */
extern int sntMax(int a, int b);

/**
 *	Return min value of a and b.
 */
extern int sntMin(int a, int b);

/**
 *	@Return size in number of elements in pointer array.
 *
 *	#Remark it requires that the element in succession with the
 *	last element is a null pointer.
 */
extern unsigned int sntSymbolArraySize(const void** array);

/**
 *	Load file content from filesystem.
 *
 *	@Return number of bytes loaded.
 */
extern long int sntLoadFile(const char* cfilename, void** pbuf);

/**
 *	Memset memory for data chunk containing sensitive information.
 *	The memory will be memset three times in succession.
 */
extern void sntMemZero(void* __restrict__ pbuf, size_t size);

#endif
