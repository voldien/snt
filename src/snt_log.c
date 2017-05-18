#include"snt_log.h"
#include<stdarg.h>

void sntVerbosityLevelSet(unsigned int verbosity){
	g_verbosity = verbosity;
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
