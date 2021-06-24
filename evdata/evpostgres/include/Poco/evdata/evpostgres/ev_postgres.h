extern "C" {
#include "libpq-fe.h"
}
#include <Poco/evdata/ev_sql_access.h>
#include <Poco/evnet/EVLHTTPRequestHandler.h>


#ifndef EV_POSTGRES_H_INCLUDED
#define EV_POSTGRES_H_INCLUDED


#define EV_POSTGRES_CONNECTION	"POSTGRES_CONNECTION"
#define EV_POSTGRES_STATEMENT	"POSTGRES_STATEMENT"

#define IDLEN 512+1


/*
 * connection object implentation
 */
typedef struct _connection {
    PGconn *pg_conn;
    int autocommit;
    unsigned int statement_id; /* sequence for statement IDs */
	std::string s_host;
	std::string s_dbname;
	std::map<std::string, int> *cached_stmts;
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



#endif
