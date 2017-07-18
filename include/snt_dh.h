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
extern int sntDHCreate(sntDH** __restrict__ dh, int numbits);

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
extern int sntDHCreateByData(sntDH** __restrict__ dh, const void* __restrict__ p,
		const void* __restrict__ g, uint32_t plen, uint32_t glen);

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
extern int sntDHCopyCommon(sntDH* __restrict__ dh, void* __restrict__ p,
		void* __restrict__ g, uint32_t* __restrict__ plen,
		uint32_t* __restrict__ glen);

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
extern int sntDHGetExchange(sntDH* __restrict__ dh,
		void* __restrict__ exchange);

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
extern int sntDHGetComputedKey(sntDH* __restrict__ dh,
		const void* __restrict__ q, void* __restrict__ key);


#endif
