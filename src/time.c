#include "snt_time.h"
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

long int sntGetNanoTime(){
	struct timeval tSpec;
	gettimeofday(&tSpec, NULL);
	return (tSpec.tv_sec * (long int)1E6L + tSpec.tv_usec) * 1000;
}

long int sntGetUnixTime(){
	return time(NULL);
}

long int sntGetTimeResolution(){
	struct timespec spec;
	clock_getres(CLOCK_MONOTONIC, &spec);
	return ((long int)1E9 / spec.tv_nsec);
}

void sntNanoSleep(long int nanosec){
	struct timespec spec;
	spec.tv_nsec = nanosec % (long int)1E9;
	spec.tv_sec = nanosec / (long int)1E9;
	nanosleep(&spec, NULL);
}
