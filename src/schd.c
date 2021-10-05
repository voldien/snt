#define _GNU_SOURCE
#include "snt_log.h"
#include "snt_schd.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

void sntMemoryLockAll() {
	//TODO add support for multiple targets
	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
		sntLogErrorPrintf("mlockall failed, %s.\n", strerror(errno));
	}
}

void sntMemoryUnLockAll() {
	// TODO add support for multiple targets
	if (munlockall() < 0) {
		sntLogErrorPrintf("munlockall failed, %s.\n", strerror(errno));
	}
}

int sntLockMemory(const void *mem, size_t size) {
	// TODO add support for multiple targets
	int e;
	e = mlock(mem, size);
	if (e != 0) {
		sntLogErrorPrintf("mlock failed, %s.\n", strerror(errno));
		return 0;
	}

	return 1;
}

void sntSchdSetAffinity(unsigned int cpu, unsigned int core, unsigned int size) {

	/*	*/
	cpu_set_t set;
	int i;

	CPU_ZERO(&set);
	for (i = 0; i < size; i++) {
		CPU_SET(core + i, &set);
	}

	/*	*/
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		sntLogErrorPrintf("sched_setaffinity failed, %s.\n", strerror(errno));
	}
}

void sntSchdGetAffinity(unsigned int *cpu, unsigned int *cores, unsigned int *size) {

	int j;
	cpu_set_t set;

	assert(cpu && cores && size);

	CPU_ZERO(&set);
	if (sched_getaffinity(0, sizeof(set), &set) != 0) {
		sntLogErrorPrintf("sched_setaffinity failed, %s.\n", strerror(errno));
	}

	// Disabled intill needed.
	// for (j = 0; j < CPU_SETSIZE; ++j){
	// 	if (CPU_ISSET(j, &set)){

	// 	}
	// }

	*cpu = 0;
	*cores = 0;
	*size = 0;
}

int sntSchdSetThreadAttrAffinity(void *att, unsigned int cpu, unsigned int cores, unsigned int size) {

	cpu_set_t set;
	int err;
	int i;

	assert(att);

	return 1;

	CPU_ZERO(&set);
	for (i = 0; i < size; i++) {
		CPU_SET(cores + i, &set);
	}

	err = pthread_attr_setaffinity_np((pthread_attr_t *)att, sizeof(set), &set);

	return err != 0;
}
