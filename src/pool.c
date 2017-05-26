#include <assert.h>
#include <sys/mman.h>
#include <errno.h>
#include <snt_pool.h>
#include <string.h>

SNTPool* sntPoolCreate(unsigned int num, unsigned int itemsize) {

	SNTPool* alloc;
	unsigned char* tmp;
	unsigned int i;
	const int size = (itemsize + sizeof(SNTPool));

	/*	*/
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
	int e;

	e = mlock(poolallocator->pool,
			poolallocator->itemsize * poolallocator->num);
	if( e != 0){
		fprintf(stderr, "mlock failed, %s.\n", strerror(errno));
		return 0;
	}

	return 1;
}

void* sntPoolObtain(SNTPool* allactor) {

	SNTPoolNode* tmp;
	void* block;

	if (allactor->pool->next == NULL) {
		return NULL;
	}

	/*	Get next element and assigned new next element.	*/
	tmp = allactor->pool->next;
	allactor->pool->next = tmp->next;

	/*	Get data block.	*/
	block = tmp->data;
	memset(block, 0, allactor->itemsize);
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

void* sntPoolResize(SNTPool* allocator, unsigned int num, unsigned int itemsize){
	fprintf(stderr, "Not supported.\n");
	return NULL;
}

unsigned int sntPoolNumNodes(const SNTPool* pool){
	return pool->num;
}

int sntPoolGetIndex(const SNTPool* pool, const void* data){
	return ((const char*)data - (const char*)pool->pool) / pool->itemsize;
}

void sntPoolFree(SNTPool* allactor){
	free(allactor->pool);
	free(allactor);
}
