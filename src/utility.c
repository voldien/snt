#include"snt_utility.h"
#include<assert.h>
#include<errno.h>


void sntSwapPointer(void** a, void** b){
	void* tp;
	tp = *a;
	*a = *b;
	*b = tp;
}

int sntLog2MutExlusive32(unsigned int a){

	int i = 0;
	int po = 0;
	const int bitlen = 32;

	if(a == 0)
		return 0;

	for(; i < bitlen; i++){
		if((a >> i) & 0x1)
			return (i + 1);
	}

	assert(0);
}

int sntIsPower2(unsigned int a){
	return (a && ((a - 1) & a)) == 0;
}

int sntMax(int a, int b){
	return ( ( (a) > (b) ) ? (a) : (b) );
}

int sntMin(int a, int b){
	return ( ( (a) < (b) ) ? (a) : (b) );
}

unsigned int sntSymbolArraySize(const void** array){

	unsigned int i = 0;

	while(array[i] != NULL){
		i++;
	}

	return i;
}

long int sntLoadFile(const char* cfilename, void** pbuf){

	long int nbytes;
	long int size;
	FILE* f;

	/*	Open file.	*/
	f = fopen(cfilename, "rb");
	if(!f){
		fprintf(stderr, "Failed opening %s, %s.\n", cfilename, strerror(errno));
		return -1;
	}

	/*	Get size of the file.	*/
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	/*	Allocate chunk.	*/
	*pbuf = malloc(size);
	assert(*pbuf);

	/*	Read whole file and copy to allocated buffer.	*/
	nbytes = fread(*pbuf, 1, size, f);

	/*	Close file.	*/
	fclose(f);

	return nbytes;
}


void sntMemZero(void* __restrict__ pbuf, size_t size){
	memset(pbuf, 0, size);
	memset(pbuf, 0, size);
	memset(pbuf, 0, size);
}
