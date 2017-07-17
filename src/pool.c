#include <assert.h>
#include <errno.h>
#include <string.h>
#include <snt_pool.h>
#include <snt_schd.h>


SNTPool* sntPoolCreate(unsigned int num, unsigned int itemsize) {

	SNTPool* alloc;
	unsigned char* tmp;
	unsigned int i;
	const int size = (itemsize + sizeof(SNTPool));	/*	Total size of each node.	*/

	/*	Allocate pool descriptor.	*/
	alloc = malloc(sizeof(SNTPool));
	assert(alloc);

	/*	Allocate number pool nodes.	*/
	alloc->pool = calloc(num, size);
	alloc->num = num;
	alloc->itemsize = itemsize;
	assert(alloc->pool);

	/*	Create pool chain.	*/
	tmp = (unsigned char*)alloc->pool;
	for (i = 0; i < num; i++) {
		((SNTPoolNode*)tmp)->next = (SNTPoolNode*)( tmp + sizeof(SNTPoolNode) + itemsize );
		tmp += itemsize + sizeof(SNTPoolNode);
	}

	/*	Terminator of the pool.	*/
	tmp -= itemsize + sizeof(SNTPoolNode);
	((SNTPoolNode*)tmp)->next = NULL;

	return alloc;
}

int sntPoolLockMem(SNTPool* poolallocator){
	return sntLockMemory(poolallocator->pool,
			sntPoolNumNodes(poolallocator) * sntPoolItemSize(poolallocator));
}

void* sntPoolObtain(SNTPool* allocator) {

	SNTPoolNode* tmp;
	void* block;

	if (allocator->pool->next == NULL) {
		return NULL;
	}

	/*	Get next element and assigned new next element.	*/
	tmp = allocator->pool->next;
	allocator->pool->next = tmp->next;

	/*	Get data block.	*/
	block = tmp->data;
	memset(block, 0, allocator->itemsize);
	return block;
}

void* sntPoolReturn(SNTPool* allocator, void* data) {

	SNTPoolNode* tmp;

	/*	Decrement with size of a pointer
	 *	to get pointer for the next element.*/
	tmp = (SNTPoolNode*)(((char*) data) - sizeof(void*));

	/*	Update next value.	*/
	tmp->next = allocator->pool->next;
	allocator->pool->next = tmp;

	memset(tmp->data, 0, allocator->itemsize);
	return tmp;
}

void* sntPoolResize(SNTPool* pool, unsigned int num, unsigned int itemsize){
	sntLogErrorPrintf("Not supported.\n");
	return NULL;
}

unsigned int sntPoolNumNodes(const SNTPool* pool){
	return pool->num;
}

unsigned int sntPoolItemSize(const SNTPool* pool){
	return pool->itemsize;
}

int sntPoolGetIndex(const SNTPool* pool, const void* data){
	return ((const char*)data - (const char*)pool->pool) / pool->itemsize;
}

static void* sntPoolItemByIndex(SNTPool* pool, unsigned int index){
	return ((char*)pool->pool) + ( (pool->itemsize + sizeof(void*)) * index + sizeof(void*));
}

void sntPoolFree(SNTPool* pool){

	sntPoolZeroFrame(pool);

	free(pool->pool);
	free(pool);
}

void sntPoolZeroFrame(SNTPool* pool){
	unsigned int i;

	for(i = 0; i < sntPoolNumNodes(pool); i++){
		sntMemZero(sntPoolItemByIndex(pool, i), sntPoolItemSize(pool));
	}
}
