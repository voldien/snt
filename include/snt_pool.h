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
#ifndef _SNT_POOL_H_
#define _SNT_POOL_H_ 1
#include <stdio.h>
#include <stdlib.h>

/**
 *	Pool node element.
 */
typedef struct snt_pool_node_t{
	struct snt_pool_node_t* next;	/*	Next item in the pool frame.	*/
	void* data[];					/*	Base pointer for the element.	*/
}SNTPoolNode;

/**
 *	Pool allocator container.
 */
typedef struct snt_pool_allocator_t{
	unsigned int num;		/*	Number of allocated elements in pool.	*/
	unsigned int itemsize;	/*	Size of each element in pool.	*/
	SNTPoolNode* pool;		/*	Pool frame.	*/
}SNTPool;


/**
 *	Create Poll allocator.
 *	[next|data]
 *
 *	@Return non null pointer if successfully.
 */
extern SNTPool* sntPoolCreate(unsigned int num,
		unsigned int itemsize);

/**
 *	Lock pool frame from being swapped to
 *	swap storage.
 */
extern int sntPoolLockMem(SNTPool* poolallocator);

/**
 *	Obtain the next element from pool frame.
 *
 *	If the returned  value is null,
 *	then the allocator is full.
 *
 *	\allocator
 *
 *	Remark: The item may not be memset to 0.
 *
 *	@Return Non null pointer if pool is not full.
 */
extern void* sntPoolObtain(SNTPool* allocator);

/**
 *	Return item to pool. Item will be memset
 *	to zero.
 *
 *	\allocator
 *
 *	@Return current next element in allocator.
 */
extern void* sntPoolReturn(SNTPool* allocator,
		void* data);

/**
 *	Resize the current pool frame size without removing
 *	current data in the pool frame iff the num is greater
 *	than the current number of elements.
 */
extern void* sntPoolResize(SNTPool* allocator, unsigned int num, unsigned int itemsize);

/**
 *	@Return number of nodes.
 */
extern unsigned int sntPoolNumNodes(const SNTPool* pool);

/**
 *	@Return item size in bytes.
 */
extern unsigned int sntPoolItemSize(const SNTPool* pool);

/**
 *	Get the node index of a valid node.
 */
extern int sntPoolGetIndex(const SNTPool* pool, const void* data);

/**
 *	Free pool.
 *
 *	\allocator
 *
 *	Remark: this function will call 'free' on allocator
 *	and pool frame pointer. The allocator pointer will be
 *	invalid afterward.
 */
extern void sntPoolFree(SNTPool* pool);

/**
 *	Set the whole pool frame to zero.
 */
extern void sntMemsetPoolFrame(SNTPool* pool);

#endif
