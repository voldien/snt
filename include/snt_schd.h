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
#ifndef _SNT_SCHD_H_
#define _SNT_SCHD_H_ 1
#include"snt_def.h"

/**
 *	Lock memory. This will prevent lazy allocation
 *	to take place. This means that all memory associated with the
 *	program gets loaded to memeory and are not allowed to be
 *	swapped to a storage medium.
 */
extern void sntMemoryLockAll(void);

/**
 *	Unlock all memory.
 */
extern void sntMemoryUnLockAll(void);

/**
 *	Lock memory adddress region.
 */
extern int sntLockMemory(const void* mem, size_t size);

/**
 *	Set process affinity mapping.
 */
extern void sntSchdSetAffinity(unsigned int cpu, unsigned int cores,
		unsigned int size);

/**
 *
 */
extern void sntSchdGetAffinity(unsigned int* cpu, unsigned int* cores,
		unsigned int* size);

/**
 *
 */
extern int sntSchdSetThreadAttrAffinity(void* att, unsigned int cpu,
		unsigned int cores, unsigned int size);

#endif
