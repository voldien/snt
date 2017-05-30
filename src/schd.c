#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include<assert.h>
#include "snt_schd.h"

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


void sntSchdSetThreadAttrAffinity(void* att, unsigned int cpu,
		unsigned int cores, unsigned int size){

	assert(att);



}
