extern "C" {
#include "libpq-fe.h"
#include "catalog/pg_type_d.h"
}
#include <Poco/evdata/ev_sql_access.h>
#include <Poco/evnet/EVLHTTPRequestHandler.h>


#ifndef EV_POSTGRES_H_INCLUDED
#define EV_POSTGRES_H_INCLUDED


#define EV_POSTGRES_CONNECTION	"POSTGRES_CONNECTION"
#define EV_POSTGRES_STATEMENT	"POSTGRES_STATEMENT"

#define IDLEN 512+1

/*
#define BOOLOID			16
#define INT2OID			21
#define INT4OID			23
#define INT8OID			20
#define FLOAT4OID		700
#define FLOAT8OID		701
*/
#define DECIMALOID		NUMERICOID

/*
 * connection object implentation
 */
typedef struct _connection {
    PGconn *pg_conn;
    int autocommit;
    unsigned int statement_id; /* sequence for statement IDs */
	std::string * s_host;
	std::string * s_dbname;
	std::map<std::string, int> *cached_stmts;
	int conn_in_error;
} connection_t;

/*
 * statement object implementation
 */
typedef struct _statement {
    connection_t *conn;
    PGresult *result;
    char *name;
    char *source; /* statement ID */
    int tuple; /* number of rows returned */
} statement_t;



class pg_queue_holder : public Poco::evnet::evl_db_conn_pool::queue_holder {
	public:
	virtual Poco::evnet::evl_db_conn_pool::queue_holder* clone()
	{
		return (Poco::evnet::evl_db_conn_pool::queue_holder*)(new pg_queue_holder());
	}
	virtual ~pg_queue_holder() {
		PGconn * conn = (PGconn*)dequeue(_queue);
		while (conn) {
			PQfinish(conn);
			conn = (PGconn*)dequeue(_queue);
		}
		wf_destroy_ev_queue(_queue);
	}
};

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

typedef short NumericDigit;
static const int round_powers[4] = {0, 1000, 100, 10};

typedef struct NumericVar {
	int ndigits;            /* # of digits in digits[] - can be 0! */
	int weight;             /* weight of first digit */
	int sign;               /* NUMERIC_POS, NUMERIC_NEG, or NUMERIC_NAN */
	int dscale;             /* display scale */
	NumericDigit *buf;			/* start of palloc'd space for digits[] */
	NumericDigit *digits;		/* base-NBASE digits */
} NumericVar;

static NumericVar const_nan = {0, 0, NUMERIC_NAN, 0, NULL, NULL};

#define free_numericvar(nv) {\
	if ((nv)->buf) free((nv)->buf); \
	if ((nv)->digits) free((nv)->digits); \
}

struct lu_bind_variable_s {
	int    type;
	void*  val;
	size_t size;
};

typedef struct lu_bind_variable_s lua_bind_var_s_type;
typedef struct lu_bind_variable_s* lua_bind_var_p_type;

#endif
