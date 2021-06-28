#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#include <execinfo.h>

int socket_live(int fd);
int ev_postgres_statement_create(lua_State *L, connection_t *conn, const char *stmt_id, const char *sql_query);
int dbd_postgresql_statement_create(lua_State *L, connection_t *conn, const char *sql_query);
void init_db_type(const char * db_type, Poco::evnet::evl_db_conn_pool::queue_holder *qhf);
void * get_conn_from_pool(const char * db_type, const char * host, const char * dbname);
void add_conn_to_pool(const char * db_type, const char * host, const char * dbname, void * conn);
const std::string * get_stmt_id_from_cache(const char * statement);

static PGconn * initiate_connection(const char * host, const char * dbname,  const char * user, const char* password);
static int open_connection_finalize(lua_State *L, int status, lua_KContext ctx);
static int open_connection_initiate(lua_State *L);
static int connection_close(lua_State *L);
static int connection_gc(lua_State *L);
static int connection_tostring(lua_State *L);
static int orchestrate_connection_process(lua_State *L, int step_to_continue);
static int orig_connection_close(lua_State *L);
static int close_connection(connection_t *conn);

/*
 * instance methods
 */
static PGconn * initiate_connection(const char * host, const char * port, const char * dbname,  const char * user, const char* password)
{
	PGconn *p = NULL;

	const char* keywords[] = { "host", "port", "dbname", "user", "password", NULL };
	const char* values[] = { host, port, dbname, user, password, NULL };

	p = PQconnectStartParams(keywords, values, 0);
	//p = PQconnectdbParams(keywords, values, 0);
	if (p == NULL) {
		DEBUGPOINT("COULD NOT ALLOCATE MEMORY\n");
		std::abort();
	}
	else if (PQstatus(p) == CONNECTION_BAD) {
		DEBUGPOINT("COULD NOT CONNECT\n");
		PQfinish(p);
		p = NULL;
	}

	return p;
}

static int return_opened_connection(lua_State *L, PGconn * p)
{
	const char * host = luaL_checkstring(L, 1);
	const char * port = luaL_checkstring(L, 2);
	const char * dbname = luaL_checkstring(L, 3);

	connection_t * conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));
	memset(conn, 0, sizeof(connection_t));
	{
		conn->cached_stmts = new (std::map<std::string, int>)();
		conn->pg_conn = p;
		conn->s_host = new std::string(host);
		conn->s_dbname = new std::string(dbname);
		conn->autocommit = 0;
		conn->conn_in_error = 0;
		conn->statement_id = 0;
	}
	luaL_getmetatable(L, EV_POSTGRES_CONNECTION);
	lua_setmetatable(L, -2);
	//DEBUGPOINT("CONNECTION SUCCEEDED top=[%d]\n", lua_gettop(L));

	return 1;
}

static int open_connection_finalize(lua_State *L, int status, lua_KContext ctx)
{
	//DEBUGPOINT("open_connection_finalize\n");
	PGconn * p = (PGconn *)ctx;
	int sock = PQsocket(p);
	PostgresPollingStatusType ps;
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	ps = PQconnectPoll(p);
	if (ps != PGRES_POLLING_FAILED && ps != PGRES_POLLING_OK) {
		if (CONNECTION_BAD == PQstatus(p)) {
			DEBUGPOINT("Connection to Postgres failed\n");
			PQfinish(p);
			lua_pushnil(L);
			return 1;
		}
		//DEBUGPOINT("open_connection_finalize sock=[%d]\n", PQsocket(p));
		int pollfor = 0;
		//Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
		switch (ps) {
			case PGRES_POLLING_WRITING:
				pollfor = Poco::evnet::EVLHTTPRequestHandler::WRITE;
				break;
			case PGRES_POLLING_READING:
				pollfor = Poco::evnet::EVLHTTPRequestHandler::READ;
				break;
			default:
				pollfor = Poco::evnet::EVLHTTPRequestHandler::READWRITE;
				break;
		}
		//DEBUGPOINT("open_connection_finalize sock=[%d] pollfor=[%d]\n", PQsocket(p), pollfor);
		reqHandler->pollSocketForReadOrWrite(NULL, PQsocket(p), pollfor);
		return lua_yieldk(L, 0, (lua_KContext)p, open_connection_finalize);
	}
	//DEBUGPOINT("DONE OPENING\n");
	if (ps != PGRES_POLLING_OK) {
		DEBUGPOINT("Connection to Postgres failed\n");
		PQfinish(p);
		lua_pushnil(L);
		return 1;
	}
	if (-1 == PQsetnonblocking(p, 1)) {
		DEBUGPOINT("Could not make the connection nonblocking\n");
		PQfinish(p);
		lua_pushnil(L);
		return 1;
	}

	return return_opened_connection(L, p);
}

/*
std::map<std::string, int> *g_cached_stmts = NULL;
PGconn *g_pg_conn = NULL;
std::string *g_s_host = NULL;
std::string *g_s_dbname = NULL;
unsigned int g_s_statement_id = 0;
int g_s_autocommit = 0;
int g_s_conn_in_error = 0;
*/

static int open_connection_initiate(lua_State *L)
{
    int n = lua_gettop(L);
	if (n != 5) {
		lua_pushnil(L);
		lua_pushstring(L, "new: Number of parameters expected: 4");
		return 2;
	}

	const char * host = luaL_checkstring(L, 1);
	const char * port = luaL_checkstring(L, 2);
	const char * dbname = luaL_checkstring(L, 3);
	const char * user = luaL_checkstring(L, 4);
	const char * password = luaL_checkstring(L, 5);
	connection_t * conn = (connection_t *) get_conn_from_pool(POSTGRES_DB_TYPE_NAME, host, dbname);
	if ( conn && !socket_live(PQsocket(conn->pg_conn))) {
		DEBUGPOINT("SOCKET IS IN ERROR\n");
		close_connection(conn);
		conn = NULL;
		/*
		 * This abort is only for debug purpose.
		 * It should eventually be removed.
		 */
		std::abort();
	}

	DEBUGPOINT("CONN = [%p]\n", conn);

	//if (g_pg_conn == NULL)
	if (conn == NULL) {
		DEBUGPOINT("DID NOT FIND CONNECTION from pool\n");
		PGconn * p = initiate_connection(host, port, dbname, user, password);
		{
			return open_connection_finalize(L, 0, (lua_KContext)p);
		}
		/*
		{
			connection_t * n_conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));
			n_conn->autocommit = 0;
			n_conn->conn_in_error = 0;
			{
				n_conn->cached_stmts = new (std::map<std::string, int>)();
				n_conn->pg_conn = p;
				n_conn->s_host = new std::string(host);
				n_conn->s_dbname = new std::string(dbname);
			}

			luaL_getmetatable(L, EV_POSTGRES_CONNECTION);
			lua_setmetatable(L, -2);

			return 1;
		}
		*/
	}
	else {
		DEBUGPOINT("FOUND CONNECTION [%p][%p] from pool\n", conn, (void*)conn->pg_conn);
		connection_t * n_conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));
		{
			{
				n_conn->cached_stmts = conn->cached_stmts;
				n_conn->pg_conn = conn->pg_conn;
				n_conn->s_host = conn->s_host;
				n_conn->s_dbname = conn->s_dbname;
				n_conn->statement_id = conn->statement_id;
				n_conn->autocommit = conn->autocommit;
				n_conn->conn_in_error = conn->conn_in_error;

				/*
				*/
			}
			/*
			{
				n_conn->cached_stmts = g_cached_stmts ;
				n_conn->pg_conn = g_pg_conn ;
				n_conn->s_host = g_s_host ;
				n_conn->s_dbname = g_s_dbname ;
				n_conn->statement_id = g_s_statement_id;
				n_conn->autocommit = g_s_autocommit;
				n_conn->conn_in_error = g_s_conn_in_error;
			}
			*/
		}
		free(conn);

		luaL_getmetatable(L, EV_POSTGRES_CONNECTION);
		lua_setmetatable(L, -2);

		return 1;
	}
}

static int run(connection_t *conn, const char *command)
{
	PGresult *result = PQexec(conn->pg_conn, command);
	ExecStatusType status;

	if (!result)
		return 1;

	status = PQresultStatus(result);
	PQclear(result);

	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
		return 1;

	return 0;
}

static int close_connection(connection_t *conn)
{
    int disconnect = 0;   
    if (conn->pg_conn) {
		/*
		 * if autocommit is turned off, we probably
		 * want to rollback any outstanding transactions.
		 */
		//if (!conn->autocommit)
			//rollback(conn);

		PQfinish(conn->pg_conn);
		disconnect = 1;
		conn->pg_conn = NULL;
    }

	if (conn->cached_stmts) {
		delete conn->cached_stmts;
		delete conn->s_host;
		delete conn->s_dbname;
	}

	return disconnect;

}

static int orig_connection_close(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);

	DEBUGPOINT("CLOSING CONNECTION [%p][%p]\n", conn, conn->pg_conn);
	int disconnect = close_connection(conn);
    lua_pushboolean(L, disconnect);
    return 1;
}


static int connection_close(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
	//socket_live(PQsocket(conn->pg_conn));
	if (conn->conn_in_error == 1) {
		return orig_connection_close(L);
	}
	else {
		connection_t *n_conn = (connection_t *)malloc(sizeof(connection_t));
		{
			n_conn->cached_stmts = conn->cached_stmts;
			n_conn->pg_conn = conn->pg_conn;
			n_conn->s_host = conn->s_host;
			n_conn->s_dbname = conn->s_dbname;
			n_conn->statement_id = conn->statement_id;
			n_conn->autocommit = conn->autocommit;
			n_conn->conn_in_error = conn->conn_in_error;
		}
		/*
		{
			g_cached_stmts = conn->cached_stmts;
			g_pg_conn = conn->pg_conn;
			g_s_host = conn->s_host;
			g_s_dbname = conn->s_dbname;
			g_s_statement_id = conn->statement_id;
			g_s_autocommit = conn->autocommit;
			g_s_conn_in_error = conn->conn_in_error;
		}
		*/
		add_conn_to_pool(POSTGRES_DB_TYPE_NAME, n_conn->s_host->c_str(), n_conn->s_dbname->c_str(), n_conn);
		//DEBUGPOINT("ADDED CONNECTION [%p][%p] TO POOL\n", n_conn, n_conn->pg_conn);
		/*
		*/
		//c = conn->pg_conn;
	}
	return 0;
}

static int connection_gc(lua_State *L)
{
	//DEBUGPOINT("Here in GC\n");
	int ret =  connection_close(L);
	//const char * c = "SELECT user_name from BIOP_ADMIN.BIOP_USER_PROFILES";
	//const void * v = get_stmt_id_from_cache(L, c);
	//DEBUGPOINT("AT THE CLOSE[%p][%s] IN CACHE\n", v, c);
	return ret;
}

static int connection_tostring(lua_State *L)
{
    void *conn = (void *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
    lua_pushfstring(L, "%s:%p", EV_POSTGRES_CONNECTION, conn);

    return 1;
}

/*
 * ok = connection:ping()
 */
static int connection_ping(lua_State *L) {
	connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
	int ok = 0;   

	if (conn->pg_conn) {
		ConnStatusType status = PQstatus(conn->pg_conn);

		if (status == CONNECTION_OK)
			ok = 1;
	}

	lua_pushboolean(L, ok);
	return 1;
}

/*
 * statement = connection:prepare(sql_string)
 */
static int connection_prepare(lua_State *L) {
	//DEBUGPOINT("connection_prepare [%s]\n", luaL_checkstring(L, 3));
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);

    if (conn->pg_conn) {
		//DEBUGPOINT("[%s]\n", luaL_checkstring(L, 3));
		return ev_postgres_statement_create(L, conn, luaL_checkstring(L, 2), luaL_checkstring(L, 3));
    }

    lua_pushnil(L);    
    lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
    return 2;
}

/*
 * quoted = connection:quote(str)
 */
static int connection_quote(lua_State *L) {
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
    size_t len;
    const char *from = luaL_checklstring(L, 2, &len);
    char *to = (char *)calloc(len*2+1, sizeof(char));
    int err = 0;
    int quoted_len;

    if (!conn->pg_conn) {
        luaL_error(L, EV_SQL_ERR_DB_UNAVAILABLE);
    }

    quoted_len = PQescapeStringConn(conn->pg_conn, to, from, len, &err);

    if (err) {
        free(to);
        
       luaL_error(L, EV_SQL_ERR_QUOTING_STR, PQerrorMessage(conn->pg_conn));
    }

    lua_pushlstring(L, to, quoted_len);
    free(to);

    return 1;
}

extern "C" int ev_postgres_connection(lua_State *L);
int ev_postgres_connection(lua_State *L)
{
	pg_queue_holder qhf;
	static int db_initialized = 0;
	static const luaL_Reg connection_methods[] = {
		{"__gc", connection_gc},
		{"__tostring", connection_tostring},
		{"ping", connection_ping},
		{"prepare", connection_prepare},
		{"quote", connection_quote},
		{NULL, NULL}
	};

	static const luaL_Reg connection_class_methods[] = {
		{"new", open_connection_initiate},
		{NULL, NULL}
	};

	int n = lua_gettop(L);
	luaL_newmetatable(L, EV_POSTGRES_CONNECTION);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	luaL_setfuncs(L, connection_methods, 0);
	lua_settop(L, n);

	lua_newtable(L);
	luaL_setfuncs(L, connection_class_methods, 0);

	if (!db_initialized) init_db_type(POSTGRES_DB_TYPE_NAME, &qhf);
	db_initialized = 1;

	return 1;    
}



