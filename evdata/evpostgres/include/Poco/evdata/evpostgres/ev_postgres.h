extern "C" {
#if defined (PG_VERSION) && (PG_VERSION == 12) 
#include "postgresql/libpq-fe.h"
#include "postgresql/12/server/catalog/pg_type_d.h"
#else
#include "libpq-fe.h"
#include "catalog/pg_type_d.h"
#endif
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



class pg_queue_holder : public Poco::evnet::evl_pool::queue_holder {
	public:
	virtual Poco::evnet::evl_pool::queue_holder* clone()
	{
		return (Poco::evnet::evl_pool::queue_holder*)(new pg_queue_holder());
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


#endif
