#include "snt_log.h"
#include "snt_parser.h"

/**
 *	Get number of parameter in argument.
 *	@Return number of comma - 1.
 */
static unsigned int sntNumParam(const char *arg) {

	/*	*/
	register unsigned int n = 0;
	register const char *comma = arg;

	/*	Get first comma.	*/
	comma = strstr(comma, ",");
	n++;

	/*	Iterate.	*/
	while (comma) {
		n++;
		comma++;
		comma = strstr(comma, ",");
	}

	return n;
}

/**
 *	Get param by nth index.
 */
static void sntGetParamByIndex(const char *SNT_RESTRICT arg, char *SNT_RESTRICT param, unsigned int index) {

	unsigned int i;
	const char *tmp = arg;
	const char *end;
	const char *beg = arg;

	/*	Iterate through each till comma infront
	 *	parameter.
	 */
	for (i = 0; i < index; i++) {
		tmp = strstr(tmp, ",");
		tmp++;
		beg = tmp;
	}

	/*	Get end of paramater by next comma or null terminator.	*/
	tmp = strstr(tmp, ",");
	end = tmp ? (tmp) : &arg[strlen(arg)];

	/*	Copy paramater.	*/
	memcpy(param, beg, (end - beg));
	param[end - beg] = '\0';
}

unsigned int sntParserBitWiseMultiParam(const char *SNT_RESTRICT arg, const char **SNT_RESTRICT opts) {

	unsigned int i = 0;	  /*	*/
	unsigned int j = 0;	  /*	*/
	unsigned int res = 0; /*	*/
	unsigned int nparam;  /*	*/
	char param[64];		  /*	*/

	/*	Get number of parameter in argument.	*/
	nparam = sntNumParam(arg);
	if (nparam <= 0) {
		return 0;
	}

	/*	Check if none option exist.	*/
	if (strstr(arg, "none")) {
		return 0;
	}

	/*	Check if all option exist.	*/
	if (strstr(arg, "all")) {
		return (unsigned int)(~0x0);
	}

	/*	Iterate through each parameter.	*/
	for (i = 0; i < nparam; i++) {

		sntGetParamByIndex(arg, param, i);
		j = 0;
		do {

			/*	*/
			if (strcmp(opts[j], param) == 0) {
				break;
			}
			j++;
			if (opts[j] == NULL) {
				sntLogErrorPrintf("Invalid option, %s.\n", param);
				exit(EXIT_FAILURE);
			}

			/*	*/
		} while (opts[j]);

		/*	*/
		res |= (1 << (j - 1));
	}

	return res;
}
