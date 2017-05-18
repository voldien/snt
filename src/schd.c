#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include "snt_schd.h"


void sntSchdSetAffinity(unsigned int cpu, unsigned int cores, unsigned int size){

	/*	*/
	cpu_set_t set;

	/*
	CPU_ZERO(&set);
	CPU_SET(&set, 0);
	*/

	sched_setaffinity(0, sizeof(set), &set);
}

