#ifndef EV_TYPEUTILS_H_INCLUDED
#define EV_TYPEUTILS_H_INCLUDED

#include <Poco/evdata/ev_sql_access.h>

extern "C" {

#ifdef TARGET_OS_OSX // {

#if defined (PG_VERSION) && (PG_VERSION == 12)  // {

#include "postgresql12/libpq-fe.h"
#include "postgresql12/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 13) // } {

#include "postgresql13/libpq-fe.h"
#include "postgresql13/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 14) // } {

#include "postgresql14/libpq-fe.h"
#include "postgresql14/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 15) // } {

#include "postgresql15/libpq-fe.h"
#include "postgresql15/server/catalog/pg_type_d.h"

#else // } {

#error

#endif // }

#else // } {

#if defined (PG_VERSION) && (PG_VERSION == 12)  // {

#include "postgresql/libpq-fe.h"
#include "postgresql/12/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 13) // } {

#include "postgresql/libpq-fe.h"
#include "postgresql/13/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 14) // } {

#include "postgresql/libpq-fe.h"
#include "postgresql/14/server/catalog/pg_type_d.h"

#elif defined (PG_VERSION) && (PG_VERSION == 15) // } {

#include "postgresql/libpq-fe.h"
#include "postgresql/15/server/catalog/pg_type_d.h"

#else // } {

#error

#endif // }


#endif // }

}



/* Extremely annoying warning "conversion from 'int ' to 'short'" on
 * Visual Studio 6.  Normally this warning is useful but not in this
 * case.  Disable it.
 */
#if defined(PQT_MSVC) && PQT_MSVC <= 1200
#	pragma warning (disable : 4244)
#endif

/*
 * Macros and structures for receiving numeric field in binary
 */
#define NBASE		10000
#define HALF_NBASE	5000
#define DEC_DIGITS	4			/* decimal digits per NBASE digit */
#define MUL_GUARD_DIGITS	2	/* these are measured in NBASE digits */
#define DIV_GUARD_DIGITS	4

/*
 * Hardcoded precision limit - arbitrary, but must be small enough that
 * dscale values will fit in 14 bits.
 */
#define NUMERIC_MAX_PRECISION		1000

/*
 * Sign values and macros to deal with packing/unpacking n_sign_dscale
 */
#define NUMERIC_SIGN_MASK	0xC000
#define NUMERIC_POS			0x0000
#define NUMERIC_NEG			0x4000
#define NUMERIC_NAN			0xC000
#define NUMERIC_DSCALE_MASK 0x3FFF
#define NUMERIC_SIGN(n)		((n)->n_sign_dscale & NUMERIC_SIGN_MASK)
#define NUMERIC_DSCALE(n)	((n)->n_sign_dscale & NUMERIC_DSCALE_MASK)
#define NUMERIC_IS_NAN(n)	(NUMERIC_SIGN(n) != NUMERIC_POS &&	\
							 NUMERIC_SIGN(n) != NUMERIC_NEG)

#ifndef TRUE
#	define TRUE 1
#endif

#ifndef FALSE
#	define FALSE 0
#endif

#ifndef NULL_LEN
#	define NULL_LEN (-1)
#endif

typedef short DecimalDigit;
static const int round_powers[4] = {0, 1000, 100, 10};

typedef struct NumericVar {
	int ndigits;            /* # of digits in digits[] - can be 0! */
	int weight;             /* weight of first digit */
	int sign;               /* NUMERIC_POS, NUMERIC_NEG, or NUMERIC_NAN */
	int dscale;             /* display scale */
	DecimalDigit *buf;			/* start of palloc'd space for digits[] */
	DecimalDigit *digits;		/* base-NBASE digits */
} NumericVar;

static NumericVar const_nan = {0, 0, NUMERIC_NAN, 0, NULL, NULL};

#define free_numericvar(nv) {\
	if ((nv)->buf) free((nv)->buf); \
	if ((nv)->digits) free((nv)->digits); \
}




/* DATE RELATED DEFINITIONS */

#define UNIX_EPOCH_JDATE        2440588 /* == date2j(1970, 1, 1) */
#define POSTGRES_EPOCH_JDATE    2451545 /* == date2j(2000, 1, 1) */
#define DU_EPOCH_JDATE 1721426 /* == date2j(0001, 1, 1) */
#define USECS_PER_DAY           86400000000



#endif
