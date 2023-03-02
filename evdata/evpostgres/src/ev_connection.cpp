#include <string.h>
#include <assert.h>
#include "Poco/evdata/evpostgres/ev_postgres.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#include <execinfo.h>

#define DELIMITER "|||"

int socket_live(int fd);
int ev_postgres_statement_create(lua_State *L, connection_t *conn, const char *stmt_id, const char *sql_query);
int dbd_postgresql_statement_create(lua_State *L, connection_t *conn, const char *sql_query);
void init_pool_type(const char * db_type, Poco::evnet::evl_pool::queue_holder *qhf);
void * get_conn_from_pool(const char * db_type, const char * host, const char * dbname);
void add_conn_to_pool(const char * db_type, const char * host, const char * dbname, void * conn);
const std::string * get_stmt_id_from_cache(const char * statement);
void clear_statements_map();
void clear_types_map();
void register_cleanup_func(void * f);

static PGconn * initiate_connection(const char * host, const char * dbname,  const char * user, const char* password);
static int open_connection_finalize(lua_State *L, int status, lua_KContext ctx);
static int open_connection_initiate(lua_State *L);
static int connection_close(lua_State *L);
static int connection_gc(lua_State *L);
static int connection_tostring(lua_State *L);
static int orchestrate_connection_process(lua_State *L, int step_to_continue);
static int orig_connection_close(lua_State *L);
static int close_connection(connection_t *conn);

static std::map<std::string, int > keys_map;

static void concat_tokens(char * target, const char * host, const char * dbname)
{
	strcpy(target, host);
	strcat(target, DELIMITER);
	strcat(target, dbname);
}

static void split_tokens(char * tokens_str, char * host, char * dbname)
{
	char * tok = strtok(tokens_str, DELIMITER);
	strcpy(host, tok);
	tok = strtok(NULL, DELIMITER);
	strcpy(dbname, tok);

	tok = strtok(NULL, DELIMITER);
	assert(tok == NULL);

	return ;
}

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
	const char * host = luaL_checkstring(L, -5);
	const char * port = luaL_checkstring(L, -4);
	const char * dbname = luaL_checkstring(L, -3);

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
		//Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
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
	/*
	if (CONNECTION_OK != PQstatus(p)) {
		DEBUGPOINT("Could not establish Postgresql connection\n");
		PQfinish(p);
		lua_pushnil(L);
		return 1;
	}
	*/

	return return_opened_connection(L, p);
}

static int open_connection_initiate(lua_State *L)
{
    int n = lua_gettop(L);
	if (n != 5) {
		lua_pushnil(L);
		lua_pushstring(L, "new: Number of parameters expected: 4");
		return 2;
	}

	const char * host = luaL_checkstring(L, -5);
	const char * port = luaL_checkstring(L, -4);
	const char * dbname = luaL_checkstring(L, -3);
	const char * user = luaL_checkstring(L, -2);
	const char * password = luaL_checkstring(L, -1);
	connection_t * conn = (connection_t *) get_conn_from_pool(POSTGRES_DB_TYPE_NAME, host, dbname);
	if ( conn && !socket_live(PQsocket(conn->pg_conn))) {
		DEBUGPOINT("SOCKET IS IN ERROR\n");
		close_connection(conn);
		free(conn);
		conn = NULL;
	}

	//DEBUGPOINT("CONN = [%p]\n", conn);
	if (conn == NULL) {
		//DEBUGPOINT("DID NOT FIND CONNECTION from pool\n");
		PGconn * p = initiate_connection(host, port, dbname, user, password);
		{
			return open_connection_finalize(L, 0, (lua_KContext)p);
		}
	}
	else {
		//DEBUGPOINT("FOUND CONNECTION [%p][%p] from pool\n", conn, (void*)conn->pg_conn);
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
			}
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
	}
	delete conn->s_host;
	delete conn->s_dbname;

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
		//PGTransactionStatusType stat = PQtransactionStatus(conn);
		switch (PQtransactionStatus(conn->pg_conn)) {
			case PQTRANS_ACTIVE:
			case PQTRANS_INTRANS:
			case PQTRANS_INERROR:
			case PQTRANS_UNKNOWN:
				DEBUGPOINT("ALL NOT OK\n");
				return orig_connection_close(L);
			case PQTRANS_IDLE:
				//DEBUGPOINT("ALL OK\n");
			default:
				break;
		}
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
		add_conn_to_pool(POSTGRES_DB_TYPE_NAME, n_conn->s_host->c_str(), n_conn->s_dbname->c_str(), n_conn);
		{
			char concat_str[1024];
			concat_tokens(concat_str, n_conn->s_host->c_str(), n_conn->s_dbname->c_str());
			std::string key(concat_str);
			keys_map[key] = 1;
		}
		/*
		*/
		lua_getglobal(L, "EVR_MODE");
		int evr_mode = lua_tointeger(L, -1);
		lua_pop(L, -1);
		if (evr_mode == Poco::evnet::EVHTTPRequestHandler::SERVER_MODE)
			DEBUGPOINT("ADDED CONNECTION [%p][%p] TO POOL\n", n_conn, n_conn->pg_conn);
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
static int connection_ping(lua_State *L)
{
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
static int connection_prepare(lua_State *L)
{
	connection_t *conn = (connection_t *)luaL_checkudata(L, -3, EV_POSTGRES_CONNECTION);

	if (conn->pg_conn) {
		return ev_postgres_statement_create(L, conn, luaL_checkstring(L, -2), luaL_checkstring(L, -1));
	}

	lua_pushnil(L);    
	lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
	return 2;
}

/*
 * quoted = connection:quote(str)
 */
static int connection_quote(lua_State *L)
{
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

static int reset_connection_error(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_POSTGRES_CONNECTION);
	conn->conn_in_error = 0;
	return 0;
}

static void cleanup_connections()
{
	char host[256];
	char dbname[256];
	char concat_str[1024];

	/*
	*/
	for (auto it = keys_map.begin(); it != keys_map.end() ; ++it) {
		strcpy(concat_str, it->first.c_str());
		split_tokens(concat_str, host, dbname);

		connection_t * conn = (connection_t *) get_conn_from_pool(POSTGRES_DB_TYPE_NAME, host, dbname);
		while (conn) {
			//DEBUGPOINT("CLOSING CONNECTION\n");
			close_connection(conn);
			free(conn);
			conn = (connection_t *) get_conn_from_pool(POSTGRES_DB_TYPE_NAME, host, dbname);
		}
	}
	keys_map.clear();
	clear_statements_map();
	clear_types_map();
	return;
}

extern "C" int ev_postgres_connection(lua_State *L);
int ev_postgres_connection(lua_State *L)
{
	pg_queue_holder qhf;
	static int db_initialized = 0;
	static const luaL_Reg connection_methods[] = {
		{"__gc", connection_gc},
		{"__tostring", connection_tostring},
		{"close", connection_close},
		{"ping", connection_ping},
		{"prepare", connection_prepare},
		{"quote", connection_quote},
		{"reset_connection_error", reset_connection_error},
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

	if (!db_initialized) init_pool_type(POSTGRES_DB_TYPE_NAME, &qhf);
	db_initialized = 1;


	register_cleanup_func((void *)cleanup_connections);

	return 1;    
}



