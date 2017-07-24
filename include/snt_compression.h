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
#ifndef _SNT_COMPRESSION_H_
#define _SNT_COMPRESSION_H_ 1
#include<stdio.h>
#include<stdlib.h>

/**
 *	Compression enumerator constants.
 *	mutually exclusive.
 */
#define SNT_COMPRESSION_NONE		0x0			/*	No compression.	*/
#define SNT_COMPRESSION_LZ4			0x1			/*	LZ4 compression. Fast but lower compression ratio.	*/
#define SNT_COMPRESSION_GZIP		0x2			/*	Gzip compression. Slow but high compression ratio.	*/
#define SNT_COMPRESSION_BZIP2		0x4			/*	BZIP2 compression.	*/
#define SNT_COMPRESSION_ALL								\
		SNT_COMPRESSION_LZ4	| SNT_COMPRESSION_GZIP		\
		| SNT_COMPRESSION_BZIP2							\

/**
 *	Compression symbol table.
 */
extern const char* gs_symcompression[];

/**
 *	Initialize compression.
 *	Must be called before using sntInflate
 *	and sntDeflate.
 */
extern void sntInitCompression(unsigned int type);

/**
 *	Inflate data.
 *
 *	Remark: The max size of inflation is 1024 bytes.
 *
 *	@Return if sucesfully number of bytes. otherwise a negative number.
 */
extern int sntInflate(unsigned int compression, const char* __restrict__ source,
		char* __restrict__ dest, unsigned int len);

/**
 *	Deflate data.
 *
 *	Remark: 'source' and 'dest' can not point at the same address.
 *
 *	@Return if sucesfully number of bytes. otherwise a negative number.
 */
extern int sntDeflate(unsigned int compression, const char* __restrict__ source,
		char* __restrict__ dest, unsigned int len);

#endif
