#include"snt_utility.h"
#include"snt_protocol.h"
#include"snt_time.h"
#include<assert.h>

int sntGenerateDeltaTypeInc(unsigned int type, char* text, SNTDelta* delta,
		const SNTDelta* incr) {

	int len = 0;

	assert(type != 0);

	switch(type){
	case SNT_DELTA_TYPE_INT:
		len = sntGenerateAsciiLongInt(text, (long int)delta->i);
		delta->i += incr->i;
		break;
	case SNT_DELTA_TYPE_FLOAT:
		len = sntGenerateAsciiFloat(text, delta->f);
		delta->f += incr->f;
		break;
	case SNT_DELTA_TYPE_TIMESTAMP:
		len = sntGenerateAsciiLongInt(text, sntGetUnixTime());
		break;
	case SNT_DELTA_TYPE_HIGHTIMESTAMP:
		len = sntGenerateAsciiLongInt(text, sntGetNanoTime());
		break;
	case SNT_DELTA_TYPE_DOUBLE:
		len = sntGenerateAsciiDouble(text, delta->d);
		delta->d += incr->d;
		break;
	default:
		break;
	}

	return len;
}

int sntGenerateAsciiFloat(char* text, float digit){
	return sprintf(text, "%f;", digit);
}
float sntAsciiToFloat(const char* text){
	return strtof(text, NULL);
}

int sntGenerateAsciiDouble(char* text, double digit){
	return sprintf(text, "%f;", digit);
}
double sntAsciiToDouble(const char* text){
	return strtod(text, NULL);
}


int sntGenerateAsciiLongInt(char* text, long int digit){
	return sprintf(text, "%ld;", digit);
}
long int sntAsciiToLongInt(const char* text){
	return strtol(text, NULL, 10);
}
