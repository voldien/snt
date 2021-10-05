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
#ifndef _SNT_DIFFIE_HELLMAN_H_
#define _SNT_DIFFIE_HELLMAN_H_ 1
#include"snt_def.h"

/**
 *	Diffie hellman pointer.
 */
typedef void sntDH;

/**
 *	Create generated Diffie hellman.
 *
 *	\dh diffie hellman pointer.
 *
 *	\bitnum diffie hellman size in bits.
 *
 *	@Return none zero if successful.
 */
extern int sntDHCreate(sntDH** SNT_RESTRICT dh, int numbits);

/**
 *	Create Diffie hellman.
 *
 *	\p prime number.
 *
 *	\g primitive root modulo p.
 *
 *	\plen p in byte size.
 *
 *	\glen g in byte size.
 *
 *	@Return none zero if successful.
 */
extern int sntDHCreateByData(sntDH** SNT_RESTRICT dh, const void* SNT_RESTRICT p,
		const void* SNT_RESTRICT g, uint32_t plen, uint32_t glen);

/**
 *	Create Diffie hellman from PEM file.
 *
 *	\dh diffie hellman pointer.
 *
 *	\path filepath to pem file.
 *
 *	@Return none zero if successful.
 */
extern int sntDHCreateFromPEMFile(sntDH** SNT_RESTRICT dh, const char* path);

/**
 *	@Return size of diffie hellman in bytes.
 */
extern int sntDHSize(const sntDH* dh);

/**
 *	Release resource associated with diffie hellman.
 */
extern void sntDHRelease(sntDH* dh);

/**
 *	Copy p and g from the diffie hellman.
 *
 *	\dh diffie hellman pointer.
 *
 *	\p
 *
 *	\g
 *
 *	\plen size of p in bytes.
 *
 *	\glen size of g in bytes.
 *
 *	@Return none zero if successful.
 */
extern int sntDHCopyCommon(sntDH* SNT_RESTRICT dh, void* SNT_RESTRICT p,
		void* SNT_RESTRICT g, uint32_t* SNT_RESTRICT plen,
		uint32_t* SNT_RESTRICT glen);

/**
 *	Compute diffie hellman with random secret key.
 *
 *	@Return none zero if successful.
 */
extern int sntDHCompute(sntDH* dh);

/**
 *	Get public key.
 *
 *	\dh
 *
 *	\exchange
 *
 *	@Return none zero if successful.
 */
extern int sntDHGetExchange(sntDH* SNT_RESTRICT dh,
		void* SNT_RESTRICT exchange);

/**
 *	Compute the shared key.
 *
 *	\dh
 *
 *	\q computed public exchange number.
 *
 *	\key computed shared key.
 *
 *	@Return none zero if successful.
 */
extern int sntDHGetComputedKey(sntDH* SNT_RESTRICT dh,
		const void* SNT_RESTRICT q, void* SNT_RESTRICT key);


#endif
