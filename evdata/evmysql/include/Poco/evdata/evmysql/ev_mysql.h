#ifdef _MSC_VER /* all MS compilers define this (version) */
#include <windows.h>
#endif

#include <mysql/mysql.h>
#include <Poco/evdata/ev_sql_access.h>

#define EV_MYSQL_CONNECTION "EV.MySQL.Connection"
#define EV_MYSQL_STATEMENT "EV.MySQL.Statement"

/*
 * connection object implementation
 */
typedef struct _connection
{
    MYSQL *mysql;
} connection_t;

/*
 * statement object implementation
 */
typedef struct _statement
{
    connection_t *conn;
    MYSQL_STMT *stmt;
    MYSQL_RES *metadata; /* result dataset metadata */

    unsigned long *lengths; /* length of retrieved data
                            we have to keep this from bind time to
                            result retrival time */
} statement_t;
