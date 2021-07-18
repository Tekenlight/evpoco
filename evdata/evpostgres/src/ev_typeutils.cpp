#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>

#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evdata/evpostgres/ev_typeutils.h"

#define PIPE '|'

/*
 * strip_var
 *
 * Strip any leading and trailing zeroes from a numeric variable
 */
static void strip_var(NumericVar *var)
{
	DecimalDigit *digits = var->digits;
	int			ndigits = var->ndigits;

	/* Strip leading zeroes */
	while (ndigits > 0 && *digits == 0) {
		digits++;
		var->weight--;
		ndigits--;
	}

	/* Strip trailing zeroes */
	while (ndigits > 0 && digits[ndigits - 1] == 0)
		ndigits--;

	/* If it's zero, normalize the sign and weight */
	if (ndigits == 0) {
		var->sign = NUMERIC_POS;
		var->weight = 0;
	}

	if (ndigits != var->ndigits) {
		memcpy(var->digits, digits, (ndigits) * sizeof(DecimalDigit));
		var->ndigits = ndigits;
	}
}

/*
 * round_var
 *
 * Round the value of a variable to no more than rscale decimal digits
 * after the decimal point.  NOTE: we allow rscale < 0 here, implying
 * rounding before the decimal point.
 */
static void
round_var(NumericVar *var, int rscale)
{
	DecimalDigit *digits = var->digits;
	int			di;
	int			ndigits;
	int			carry;

	var->dscale = rscale;

	/* decimal digits wanted */
	di = (var->weight + 1) * DEC_DIGITS + rscale;

	/*
	 * If di = 0, the value loses all digits, but could round up to 1 if its
	 * first extra digit is >= 5.  If di < 0 the result must be 0.
	 */
	if (di < 0) {
		var->ndigits = 0;
		var->weight = 0;
		var->sign = NUMERIC_POS;
	}
	else {
		/* NBASE digits wanted */
		ndigits = (di + DEC_DIGITS - 1) / DEC_DIGITS;

		/* 0, or number of decimal digits to keep in last NBASE digit */
		di %= DEC_DIGITS;

		if (ndigits < var->ndigits ||
			(ndigits == var->ndigits && di > 0)) {
			var->ndigits = ndigits;

			if (di == 0)
				carry = (digits[ndigits] >= HALF_NBASE) ? 1 : 0;
			else {
				/* Must round within last NBASE digit */
				int			extra,
							pow10;

				pow10 = round_powers[di];
				extra = digits[--ndigits] % pow10;
				digits[ndigits] = digits[ndigits] - (DecimalDigit) extra;
				carry = 0;
				if (extra >= pow10 / 2) {
					pow10 += digits[ndigits];
					if (pow10 >= NBASE)
					{
						pow10 -= NBASE;
						carry = 1;
					}
					digits[ndigits] = (DecimalDigit) pow10;
				}
			}

			/* Propagate carry if needed */
			while (carry) {
				carry += digits[--ndigits];
				if (carry >= NBASE) {
					digits[ndigits] = (DecimalDigit) (carry - NBASE);
					carry = 1;
				}
				else {
					digits[ndigits] = (DecimalDigit) carry;
					carry = 0;
				}
			}

			if (ndigits < 0) {
				var->digits--;
				var->ndigits++;
				var->weight++;
			}
		}
	}
}

/*
 * str2num()
 *
 *	Parse a string and put the number into a variable
 *  returns -1 on error and 0 for success.
 */
int str2num(const char *str, NumericVar *dest)
{
	const char *cp = str;
	int		have_dp = FALSE;
	int			i;
	unsigned char *decdigits;
	int			sign = NUMERIC_POS;
	int			dweight = -1;
	int			ddigits;
	int			dscale = 0;
	int			weight;
	int			ndigits;
	int			offset;
	DecimalDigit *digits;

	/*
	 * We first parse the string to extract decimal digits and determine the
	 * correct decimal weight.	Then convert to NBASE representation.
	 */

	/* skip leading spaces */
	while (*cp) {
		if (!isspace((unsigned char) *cp))
			break;
		cp++;
	}

	/*
	 * Check for NaN
	 */
	if (tolower(*cp) == 'n' && tolower(*(cp+1)) == 'a'
			&& tolower(*(cp+2)) == 'n') {
		cp += 3;
		/* Should be nothing left but spaces */
		while (*cp) {
			if (!isspace(*cp)) {
				return -1;
			}
			cp++;
		}
		*dest = const_nan;
		return 0;
	}

	switch (*cp) {
		case '+':
			sign = NUMERIC_POS;
			cp++;
			break;

		case '-':
			sign = NUMERIC_NEG;
			cp++;
			break;
	}

	if (*cp == '.') {
		have_dp = TRUE;
		cp++;
	}

	if (!isdigit((unsigned char) *cp))
		return -1;

	decdigits = (unsigned char *) malloc(strlen(cp) + DEC_DIGITS * 2);

	/* leading padding for digit alignment later */
	memset(decdigits, 0, DEC_DIGITS);
	i = DEC_DIGITS;

	while (*cp) {
		if (isdigit((unsigned char) *cp)) {
			decdigits[i++] = *cp++ - '0';
			if (!have_dp)
				dweight++;
			else
				dscale++;
		}
		else if (*cp == '.') {
			if (have_dp) {
				free(decdigits);
				return -1;
			}

			have_dp = TRUE;
			cp++;
		}
		else
			break;
	}

	ddigits = i - DEC_DIGITS;
	/* trailing padding for digit alignment later */
	memset(decdigits + i, 0, DEC_DIGITS - 1);

	/* Handle exponent, if any */
	if (*cp == 'e' || *cp == 'E') {
		long		exponent;
		char	   *endptr;

		cp++;
		exponent = strtol(cp, &endptr, 10);
		if (endptr == cp) {
			free(decdigits);
			return -1;
		}

		cp = endptr;
		if (exponent > NUMERIC_MAX_PRECISION ||
			exponent < -NUMERIC_MAX_PRECISION) {
			free(decdigits);
			return -1;
		}

		dweight += (int) exponent;
		dscale -= (int) exponent;
		if (dscale < 0)
			dscale = 0;
	}

	/* Should be nothing left but spaces */
	while (*cp) {
		if (!isspace((unsigned char) *cp)) {
			free(decdigits);
			return -1;
		}
		cp++;
	}

	/*
	 * Okay, convert pure-decimal representation to base NBASE.  First we need
	 * to determine the converted weight and ndigits.  offset is the number of
	 * decimal zeroes to insert before the first given digit to have a
	 * correctly aligned first NBASE digit.
	 */
	if (dweight >= 0)
		weight = (dweight + 1 + DEC_DIGITS - 1) / DEC_DIGITS - 1;
	else
		weight = -((-dweight - 1) / DEC_DIGITS + 1);
	offset = (weight + 1) * DEC_DIGITS - (dweight + 1);
	ndigits = (ddigits + offset + DEC_DIGITS - 1) / DEC_DIGITS;

	dest->digits = (DecimalDigit *) malloc((ndigits) * sizeof(DecimalDigit));
	dest->ndigits = ndigits;
	dest->sign = sign;
	dest->weight = weight;
	dest->dscale = dscale;

	i = DEC_DIGITS - offset;
	digits = dest->digits;

	while (ndigits-- > 0) {
		*digits++ = ((decdigits[i] * 10 + decdigits[i + 1]) * 10 +
					 decdigits[i + 2]) * 10 + decdigits[i + 3];
		i += DEC_DIGITS;
	}

	free(decdigits);

	/* Strip any leading/trailing zeroes, and normalize weight if zero */
	strip_var(dest);
	return 0;
}

/*
 * num2str() -
 *
 *	Convert a var to text representation (guts of numeric_out).
 *	CAUTION: var's contents may be modified by rounding!
 *	returns -1 on error and 0 for success.
 */
int num2str(char *out, size_t outl, NumericVar *var, int dscale)
{
	//char	   *str;
	char	   *cp;
	char	   *endcp;
	int			i;
	int			d;
	DecimalDigit dig;
	DecimalDigit d1;

	/*
	 * Handle NaN
	 */
	if (var->sign == NUMERIC_NAN) {
		strcpy(out, "NaN");
		return 0;
	}

	if (dscale < 0)
		dscale = 0;

	/*
	 * Check if we must round up before printing the value and do so.
	 */
	round_var(var, dscale);

	/*
	 * Allocate space for the result.
	 *
	 * i is set to to # of decimal digits before decimal point. dscale is the
	 * # of decimal digits we will print after decimal point. We may generate
	 * as many as DEC_DIGITS-1 excess digits at the end, and in addition we
	 * need room for sign, decimal point, null terminator.
	 */
	i = (var->weight + 1) * DEC_DIGITS;
	if (i <= 0)
		i = 1;

	if (outl <= (size_t) (i + dscale + DEC_DIGITS + 2))
		return -1;

	//str = palloc(i + dscale + DEC_DIGITS + 2);
	//cp = str
	cp = out;

	/*
	 * Output a dash for negative values
	 */
	if (var->sign == NUMERIC_NEG)
		*cp++ = '-';

	/*
	 * Output all digits before the decimal point
	 */
	if (var->weight < 0) {
		d = var->weight + 1;
		*cp++ = '0';
	}
	else {
		for (d = 0; d <= var->weight; d++) {
			dig = (d < var->ndigits) ? var->digits[d] : 0;
			/* In the first digit, suppress extra leading decimal zeroes */
			{
				int		putit = (d > 0);

				d1 = dig / 1000;
				dig -= d1 * 1000;
				putit |= (d1 > 0);
				if (putit)
					*cp++ = (char) (d1 + '0');
				d1 = dig / 100;
				dig -= d1 * 100;
				putit |= (d1 > 0);
				if (putit)
					*cp++ = (char) (d1 + '0');
				d1 = dig / 10;
				dig -= d1 * 10;
				putit |= (d1 > 0);
				if (putit)
					*cp++ = (char) (d1 + '0');
				*cp++ = (char) (dig + '0');
			}
		}
	}

	/*
	 * If requested, output a decimal point and all the digits that follow it.
	 * We initially put out a multiple of DEC_DIGITS digits, then truncate if
	 * needed.
	 */
	if (dscale > 0) {
		*cp++ = '.';
		endcp = cp + dscale;
		for (i = 0; i < dscale; d++, i += DEC_DIGITS) {
			dig = (d >= 0 && d < var->ndigits) ? var->digits[d] : 0;
			d1 = dig / 1000;
			dig -= d1 * 1000;
			*cp++ = (char) (d1 + '0');
			d1 = dig / 100;
			dig -= d1 * 100;
			*cp++ = (char) (d1 + '0');
			d1 = dig / 10;
			dig -= d1 * 10;
			*cp++ = (char) (d1 + '0');
			*cp++ = (char) (dig + '0');
		}
		cp = endcp;
	}

	/*
	 * terminate the string and return it
	 */
	*cp = '\0';
	return 0;
}

char * expand_buffer(char * out, int new_len)
{
	return (char*)realloc(out, new_len);
}

/* exposing a NumericVar struct to a libpq user, or something similar,
 * doesn't seem useful w/o a library to operate on it.  Instead, we
 * always expose a numeric in text format and let the API user decide
 * how to use it .. like strod or a 3rd party big number library.  We
 * always send a numeric in binary though.
 */
int pqt_put_numeric(short ** out_buf, char * str)
{
	int numlen;
	NumericVar num = {0};
	short *out = NULL;

	if (-1 == str2num(str, &num)) {
		if (num.digits)
			free(num.digits);
		return -1;
	}

	/* variable length data type, grow args->put.out buffer if needed */
	numlen = (int) sizeof(short) * (4 + num.ndigits);
	out = (short*)expand_buffer(NULL, numlen);
	if (out == NULL)
		return -1;

	*out++ = htons((short) num.ndigits);
	*out++ = htons((short) num.weight);
	*out++ = htons((short) num.sign);
	*out++ = htons((short) num.dscale);

	if (num.digits) {
		int i;
		for (i=0; i < num.ndigits; i++)
			*out++ = htons(num.digits[i]);
		free(num.digits);
	}
	*out_buf = out;

	return numlen;
}

/* exposing a NumericVar struct to a libpq user, or something similar,
 * doesn't seem useful w/o a library to operate on it.  Instead, we
 * always expose a numeric in text format and let the API user decide
 * how to use it .. like strod or a 3rd party big number library.
 */
int pqt_get_numeric(char **str, PGresult *result, const char *value)
{
	int i;
	short *s;
	NumericVar num;
	char buf[4096];
	size_t len;


	s = (short *) value;
	num.ndigits = ntohs(*s); s++;
	num.weight  = (short) ntohs(*s); s++;
	num.sign    = ntohs(*s); s++;
	num.dscale  = ntohs(*s); s++;
	num.digits  = (DecimalDigit *) malloc(num.ndigits * sizeof(short));
	if (!num.digits)
		return -1;

	for (i=0; i < num.ndigits; i++) {
		num.digits[i] = ntohs(*s);
		s++;
	}

	i = num2str(buf, sizeof(buf), &num, num.dscale);
	free(num.digits);

	/* num2str failed, only fails when 'str' is too small */
	if (i == -1)
		return -1;

	len = strlen(buf)+1;
	*str = (char*)PQresultAlloc(result, len);
	if (!*str)
		return -1;

	memcpy(*str, buf, len);
	return 0;

}



/*
 *
 * INTERVAL RELATED FUNCTIONS
 *
 *
 */

interval_p_type pqt_get_interval(PGresult *result, const char *value)
{
	int mons;
	int days;
	int64_t usecs;

	interval_p_type out = (interval_p_type)PQresultAlloc(result, sizeof(interval_s_type));

	memcpy(&usecs, value, sizeof(int64_t));
	memcpy(&days, value+sizeof(int64_t), sizeof(int32_t));
	memcpy(&mons, value+sizeof(int64_t)+sizeof(int32_t), sizeof(int32_t));

	out->usec = ntohll(usecs);
	out->day = ntohl(days);
	out->mon = ntohl(mons);

	/*
	printf("%s:%d usec = [%lld]\n", __FILE__, __LINE__, out->usec);
	printf("%s:%d day = [%d]\n", __FILE__, __LINE__, out->day);
	printf("%s:%d mon = [%d]\n", __FILE__, __LINE__, out->mon);
	*/

	return out;
}

int deser_interval(interval_p_type out, const char * in)
{
	if (!in) return -1;
	double sec = 0;
	char * str = strdup(in);
	char * p = str;
	char *d_ptr = NULL;
	char *us_ptr = NULL;
	char *m_ptr = str;
	double d = 0;

	out->day = 0;
	out->mon = 0;
	out->usec = 0;

	p = strchr(p, PIPE);
	if (!p) {
		free(str);
		return -1;
	}
	*p = (char)0;
	p++;
	d_ptr = p;

	p = strchr(p, PIPE);
	if (!p) {
		free(str);
		return -1;
	}
	*p = (char)0;
	p++;
	us_ptr = p;

	out->day = strtol(d_ptr, NULL, 0);
	out->mon = strtol(m_ptr, NULL, 0);
	d = strtod(us_ptr, NULL);
	out->usec = llround(d*1000000);

	free(str);
	return 0;
}

const char * pqt_put_interval(const char * in)
{
	int mons;
	int days;
	int64_t usecs;

	interval_s_type s_in;

	if (-1 == deser_interval(&s_in, in))
		return NULL;

	const char * out = (char*)malloc(sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t));

	usecs = htonll(s_in.usec);
	days = htonl(s_in.day);
	mons = htonl(s_in.mon);

	memcpy((void*)out, &usecs, sizeof(int64_t));
	memcpy((void*)(out+sizeof(int64_t)), &days, sizeof(int32_t));
	memcpy((void*)(out+sizeof(int64_t)+sizeof(int32_t)), &mons, sizeof(int32_t));

	return out;
}



