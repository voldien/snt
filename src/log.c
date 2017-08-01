#include"snt_log.h"
#include<stdarg.h>
#include<syslog.h>
#include<unistd.h>

void sntVerbosityLevelSet(unsigned int verbosity){
	g_verbosity = verbosity;
}

void sntLogEnableSys(unsigned int enable){
	if(enable){
		/*	*/
		if(getpgrp() != tcgetpgrp(STDOUT_FILENO)){
			/*	*/
			sntDebugPrintf("openlog as daemon process.\n");
			openlog("snt-server", LOG_PID, LOG_DAEMON);
		}
		else{
			/*	*/
			sntDebugPrintf("openlog as non daemon process.\n");
			openlog("snt-server", LOG_PID | LOG_PERROR, LOG_DAEMON);
		}
		/*	*/
		setlogmask (LOG_UPTO (LOG_INFO));
		atexit(closelog);

	}else{
		closelog();
	}
}

int sntLogPrintfInternal(unsigned int verbosity, const char* fmt,...){

	int l;
	va_list vl;

	if(verbosity <= g_verbosity){
		va_start(vl, fmt);
		l = vprintf(fmt, vl);
		va_end(vl);
	}

	return l;
}

int sntLogErrorPrintf(const char* fmt, ...){

	int l;
	va_list vl;

	va_start(vl, fmt);
	l = vfprintf(stderr, fmt, vl);
	va_end(vl);

	return l;
}
