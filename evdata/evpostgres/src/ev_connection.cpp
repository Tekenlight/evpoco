#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#include <execinfo.h>

int ev_postgres_statement_create(lua_State *L, connection_t *conn, const char *stmt_id, const char *sql_query);
void init_db_type(const char * db_type, Poco::evnet::evl_db_conn_pool::queue_holder *qhf);
void * get_conn_from_pool(const char * db_type, const char * host, const char * dbname);
void add_conn_to_pool(const char * db_type, const char * host, const char * dbname, void * conn);

static PGconn * initiate_connection(const char * host, const char * dbname,  const char * user, const char* password);
static int open_connection_finalize(lua_State *L, int status, lua_KContext ctx);
static int open_connection_initiate(lua_State *L);
static int connection_close(lua_State *L);
static int connection_gc(lua_State *L);
static int connection_tostring(lua_State *L);

/*
 * instance methods
 */
static PGconn * initiate_connection(const char * host, const char * dbname,  const char * user, const char* password)
{
	PGconn *p = NULL;

	const char* keywords[] = { "host", "dbname", "user", "password", NULL };
	const char* values[] = { host, dbname, user, password, NULL };

	p = PQconnectStartParams(keywords, values, 0);
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
	const char * host = luaL_checkstring(L, 1);
	const char * dbname = luaL_checkstring(L, 2);

	connection_t * conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));
	memset(conn, 0, sizeof(connection_t));
	conn->cached_stmts = new (std::map<std::string, int>)();
	conn->pg_conn = p;
	conn->s_host = host;
	conn->s_dbname = dbname;
	luaL_getmetatable(L, EV_POSTGRES_CONNECTION);
	lua_setmetatable(L, -2);
	//DEBUGPOINT("CONNECTION SUCCEEDED top=[%d]\n", lua_gettop(L));

	return 1;
}

const std::string * get_stmt_id_from_cache(const char * statement);
static int open_connection_initiate(lua_State *L)
{
    int n = lua_gettop(L);
	if (n != 4) {
		lua_pushnil(L);
		lua_pushstring(L, "new: Number of parameters expected: 4");
		return 2;
	}
	const char * host = luaL_checkstring(L, 1);
	const char * dbname = luaL_checkstring(L, 2);
	const char * user = luaL_checkstring(L, 3);
	const char * password = luaL_checkstring(L, 4);

	connection_t * conn = (connection_t *) get_conn_from_pool(POSTGRES_DB_TYPE_NAME, host, dbname);

	if (conn == NULL) {
		//DEBUGPOINT("DID NOT FIND CONNECTION from pool\n");
		PGconn * p = initiate_connection(host, dbname, user, password);
		return open_connection_finalize(L, 0, (lua_KContext)p);
	}
	else {
		//DEBUGPOINT("FOUND CONNECTION [%p] from pool\n", (void*)conn->pg_conn);
		connection_t * n_conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));
		memcpy(n_conn, conn, sizeof(connection_t));
		free(conn);

		luaL_getmetatable(L, EV_POSTGRES_CONNECTION);
		lua_setmetatable(L, -2);

		return 1;
	}
}

static int orig_connection_close(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
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
	}

    lua_pushboolean(L, disconnect);
    return 1;
}

static int connection_close(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
	connection_t *n_conn = (connection_t *)malloc(sizeof(connection_t));
	memcpy(n_conn, conn, sizeof(connection_t));
	add_conn_to_pool(POSTGRES_DB_TYPE_NAME, n_conn->s_host.c_str(), n_conn->s_dbname.c_str(), n_conn);
	DEBUGPOINT("ADDED CONNECTION [%p] TO POOL\n", n_conn->pg_conn);
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
 * statement = connection:prepare(sql_string)
 */
static int connection_prepare(lua_State *L) {
	DEBUGPOINT("connection_prepare\n");
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);

    if (conn->pg_conn) {
		return ev_postgres_statement_create(L, conn, luaL_checkstring(L, 2), luaL_checkstring(L, 3));
    }

    lua_pushnil(L);    
    lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
    return 2;
}

extern "C" int ev_postgres_connection(lua_State *L);
int ev_postgres_connection(lua_State *L)
{
	pg_queue_holder qhf;
	static int db_initialized = 0;
	static const luaL_Reg connection_methods[] = {
		{"__gc", connection_gc},
		{"__tostring", connection_tostring},
		{"prepare", connection_prepare},
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



