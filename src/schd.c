#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include "snt_schd.h"


void sntMemoryLockAll(void){
	if(mlockall(MCL_CURRENT | MCL_FUTURE) < 0){
		fprintf(stderr, "mlockall failed, %s.\n", strerror(errno));
	}
}

void sntMemoryUnLockAll(void){
	if(munlockall() < 0){
		fprintf(stderr, "munlockall failed, %s.\n", strerror(errno));
	}
}

void sntSchdSetAffinity(unsigned int cpu, unsigned int core, unsigned int size){

	/*	*/
	cpu_set_t set;
	int i;

	CPU_ZERO(&set);
	for(i = 0; i < size; i++){
		CPU_SET(core + i, &set);
	}

	/*	*/
	if(sched_setaffinity(0, sizeof(set), &set) != 0){
		fprintf(stderr, "sched_setaffinity failed, %s.\n", strerror(errno));
	}
}

void sntSchdGetAffinity(unsigned int* cpu, unsigned int* cores,
		unsigned int* size){

	int j;
	cpu_set_t set;

	assert(cpu && cores && size);

	CPU_ZERO(&set);
	if(sched_getaffinity(0, sizeof(set), &set) != 0){
		fprintf(stderr, "sched_setaffinity failed, %s.\n", strerror(errno));
	}

	for (j = 0; j < CPU_SETSIZE; ++j){
		if (CPU_ISSET(j, &set)){

		}
	}

	*cpu = 0;
	*cores = 0;
	*size = 0;

}

int sntSchdSetThreadAttrAffinity(void* att, unsigned int cpu,
		unsigned int cores, unsigned int size){

	cpu_set_t set;
	int err;
	int i;

	assert(att);

	return 1;

	CPU_ZERO(&set);
	for(i = 0; i < size; i++){
		CPU_SET(cores + i, &set);
	}

	err = pthread_attr_setaffinity_np((pthread_attr_t*)att, sizeof(set), &set);

	return err != 0;
}
