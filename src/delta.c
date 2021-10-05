#include "snt_def.h"
#include "snt_protocol.h"
#include "snt_time.h"
#include "snt_utility.h"
#include <assert.h>

int sntGenerateDeltaTypeInc(unsigned int type, char *text, SNTDelta *delta, const SNTDelta *incr) {

	int len = 0;

	assert(type);

	switch (type) {
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

void sntDeltaParse(unsigned int type, const char *SNT_RESTRICT buf, SNTDelta *SNT_RESTRICT delta) {
	switch (type) {
	case SNT_DELTA_TYPE_FLOAT:
		delta->f = sntAsciiToFloat(buf);
		break;
	case SNT_DELTA_TYPE_DOUBLE:
		delta->d = sntAsciiToFloat(buf);
		break;
	case SNT_DELTA_TYPE_HIGHTIMESTAMP:
	case SNT_DELTA_TYPE_TIMESTAMP:
	case SNT_DELTA_TYPE_INT:
		delta->i = sntAsciiToLongInt(buf);
		break;
	default:
		assert(0);
	}
}

int sntDeltaCheckChange(unsigned int type, const SNTDelta *SNT_RESTRICT prev, const SNTDelta *SNT_RESTRICT next,
						const SNTDelta *SNT_RESTRICT incre) {
	switch (type) {
	case SNT_DELTA_TYPE_INT:
		return ((next->i - prev->i) == incre->i);
	case SNT_DELTA_TYPE_FLOAT:
		return ((next->f - prev->f) == incre->f);
	case SNT_DELTA_TYPE_DOUBLE:
		return ((next->d - prev->d) == incre->d);
	case SNT_DELTA_TYPE_HIGHTIMESTAMP:
		return (next->i > prev->i);
	case SNT_DELTA_TYPE_TIMESTAMP:
		return (next->i > prev->i);
	default:
		assert(0);
	}
	return 0;
}

int sntGenerateAsciiFloat(char *text, float digit) { return sprintf(text, "%f", digit); }
float sntAsciiToFloat(const char *text) { return strtof(text, NULL); }

int sntGenerateAsciiDouble(char *text, double digit) { return sprintf(text, "%lf", digit); }
double sntAsciiToDouble(const char *text) { return strtod(text, NULL); }

int sntGenerateAsciiLongInt(char *text, long int digit) { return sprintf(text, "%ld", digit); }
long int sntAsciiToLongInt(const char *text) { return strtol(text, NULL, 10); }
