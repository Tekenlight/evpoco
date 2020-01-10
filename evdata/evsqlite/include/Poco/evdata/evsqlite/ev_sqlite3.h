extern "C" {
#include <sqlite3.h>
}
#include <Poco/evdata/ev_sql_access.h>

#ifndef EV_SQLITE3_INCLUDED
#define EV_SQLITE3_INCLUDED

namespace evpoco {
namespace evdata {
namespace evsqlite {

#define EV_SQLITE_CONNECTION	"EV.SQLite3.Connection"
#define EV_SQLITE_STATEMENT		"EV.SQLite3.Statement"

/*
 * connection object
 */
typedef struct _connection {
    sqlite3 *sqlite;
    int autocommit;
} connection_t;

/*
 * statement object
 */
typedef struct _statement {
    connection_t *conn;
    sqlite3_stmt *stmt;
    int more_data;
    int affected;
} statement_t;

}
}
}

#endif
