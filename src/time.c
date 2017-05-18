#include "snt_time.h"
#include<time.h>
#include <sys/time.h>
#include <unistd.h>

long int sntGetNanoTime(void){
	struct timeval tSpec;
	gettimeofday(&tSpec, NULL);
	return (tSpec.tv_sec * 1E6 + tSpec.tv_usec) * 1000;
}

long int sntGetUnixTime(void){
	return time(NULL);
}

long int sntGetTimeResolution(void){
	struct timespec spec;
	clock_getres(CLOCK_MONOTONIC, &spec);
	return (1E9 / spec.tv_nsec);
}
