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
#ifndef _SNT_HASH_H_
#define _SNT_HASH_H_
#include"snt_def.h"

/**
 *	Hash types.
 */
#define SNT_HASH_None		0x0		/*	No hash.	*/
#define SNT_HASH_MD4		0x1		/*	MD4 hash.	*/
#define SNT_HASH_MD5		0x2		/*	MD5 hash.	*/
#define SNT_HASH_SHA		0x3		/*	Secure hashing algorithm 128 bits.	*/
#define SNT_HASH_SHA224		0x4		/*	Secure hashing algorithm 224 bits.	*/
#define SNT_HASH_SHA256		0x5		/*	Secure hashing algorithm 256 bits.	*/
#define SNT_HASH_SHA384 	0x6		/*	Secure hashing algorithm 384 bits.	*/
#define SNT_HASH_SHA512 	0x7		/*	Secure hashing algorithm 512 bits.*/

/**
 *	Hash symbol table.
 */
extern const char* gc_hash_symbol[];

/**
 *	Compute hash out of the data
 *	block.
 *
 *	@Return hash size
 */
extern unsigned int sntHash(unsigned int hashtype, const void* __restrict__ block,
		unsigned int len, void* __restrict__ result);

/**
 *	Get fixed hashed size of given hash type.
 *
 *	@Return none zero if valid hash type.
 */
extern unsigned int sntHashGetTypeSize(unsigned int hashtype);

#endif
