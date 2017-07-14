#include"snt_rand.h"
#include<openssl/rand.h>


void sntGenRandom(unsigned char * rand, int size){

	int status;
	static int initialized = 0;

	/*	Initialize RAND.	*/
	if(!initialized){
		RAND_poll();
		initialized = 1;
	}

	/*	Generate random string.	*/
	status = RAND_bytes(rand, size);
	if(status != 1){
		printf("error : %d\n", RAND_status());
	}

	/*	Set seed.	*/
	RAND_seed((const void*)rand, status);
}
