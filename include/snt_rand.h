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
#ifndef _SNT_RAND_GENERATOR_H_
#define _SNT_RAND_GENERATOR_H_ 1
#include"snt_def.h"

/**
 *	Generate random sequence.
 *
 *	\rand memory location where to store
 *	the random data.
 *
 *	\size sizeof the memory location in bytes.
 */
extern void sntGenRandom(unsigned char* rand, int size);

extern void sntGenPseudoSecureRandom(void* random, size_t size);


#endif
