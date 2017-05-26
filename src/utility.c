#include"snt_utility.h"
#include<assert.h>


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

	for(; i < bitlen; i++){
		if((a >> i) & 0x1)
			po++;
	}

	return po;
}

int sntMax(int a, int b){
	return ( ( (a) > (b) ) ? (a) : (b) );
}

int sntMin(int a, int b){
	return ( ( (a) < (b) ) ? (a) : (b) );
}

unsigned int sntSymbolArraySize(void** array){

	unsigned int i = 0;

	while(array[i]){
		i++;
	}
	return i;
}
