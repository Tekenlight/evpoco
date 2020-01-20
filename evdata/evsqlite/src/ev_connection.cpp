#include "Poco/evdata/evsqlite/ev_sqlite3.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#include <execinfo.h>

extern "C" {
void ev_sqlite3_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams,
																connection_t *conn, const char *sql_query);
int db_sqlite3_statement_create(lua_State *L, connection_t *conn, const char *sql_query);
int completion_common_routine(lua_State* L, int status, lua_KContext ctx);
gen_lua_user_data_t* get_generic_lua_userdata(const char * name, void * data, size_t size);
}

static void v_hello_world(void* v)
{
	DEBUGPOINT("Here v = %p\n", v);
	return;
}

static int run(connection_t *conn, const char *command)
{
    int res = sqlite3_exec(conn->sqlite, command, NULL, NULL, NULL);

    return res != SQLITE_OK;
}

static int commit(connection_t *conn)
{
    return run(conn, "COMMIT TRANSACTION");
}


static int begin(connection_t *conn)
{
    int err = 0;

    if (sqlite3_get_autocommit(conn->sqlite)) {
        err = run(conn, "BEGIN TRANSACTION");
    } else {
        err = 0;
    }

    return err;
}

static int rollback(connection_t *conn)
{
    return run(conn, "ROLLBACK TRANSACTION");
}

/* 
 * connection,err = evrdbms.sqlite3(dbfile)
 */
static int connection_new(lua_State *L)
{
    int n = lua_gettop(L);

    const char *db = NULL;
    connection_t *conn = NULL;

    /* db */
    switch(n) {
    default:
	/*
	 * db is the only mandatory parameter
	 */
	db = luaL_checkstring(L, 1);
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (n >= 2) {
      if (!lua_isnil(L, 2))
	flags = luaL_checkinteger(L, 2);
    }

    conn = (connection_t *)lua_newuserdata(L, sizeof(connection_t));

    if (sqlite3_open_v2(db, &conn->sqlite, flags, NULL) != SQLITE_OK) {
	lua_pushnil(L);
	lua_pushfstring(L, EV_SQL_ERR_CONNECTION_FAILED, sqlite3_errmsg(conn->sqlite));
	return 2;
    }

	/*
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	Poco::evnet::EVServer * server = reqHandler->getServerPtr();
	server->submitRequestForTaskExecutionNR(v_hello_world, 0);
	*/

    conn->autocommit = 0;

    luaL_getmetatable(L, EV_SQLITE_CONNECTION);
    lua_setmetatable(L, -2);

    return 1;
}

static void* vs_connection_new(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    int n = get_num_generic_params(iparams);
	//DEBUGPOINT("Here n = %d\n", n);

    const char *db = NULL;
    connection_t *conn = NULL;

    /* db */
    switch(n) {
    default:
		/*
		 * db is the only mandatory parameter
		 */
		db = (char*)get_generic_task_ptr_param(iparams, 1);
		//DEBUGPOINT("Here p = %p value = %s\n", db, db); 
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (n >= 2) {
		void *p =  get_generic_task_ptr_param(iparams, 2);
		if (p) flags = (int)(long)(p);
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();

    conn = (connection_t *)malloc(sizeof(connection_t));
    if (sqlite3_open_v2(db, &conn->sqlite, flags, NULL) != SQLITE_OK) {
		free(conn);
		set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
		char str[1024];
		sprintf(str, EV_SQL_ERR_CONNECTION_FAILED, sqlite3_errmsg(conn->sqlite));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return (void*)oparams;
    }

    conn->autocommit = 0;

	//DEBUGPOINT("Here sizeof(connection_t)=%zu\n", sizeof(connection_t));
	set_lua_stack_out_param(oparams, EV_LUA_TUSERDATA,
				get_generic_lua_userdata(EV_SQLITE_CONNECTION, conn, sizeof(connection_t)));

	iparams = destroy_generic_task_in_params(iparams);

    return (void*)oparams;
}

static int initiate_connection_new(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    int n = lua_gettop(L);

	//DEBUGPOINT("Here sqlite thread mode = %d\n", sqlite3_threadsafe());

    const char *db = NULL;

    /* db */
    switch(n) {
		/*
		 * db is the only mandatory parameter
		 */
		default:
			db = luaL_checkstring(L, 1);
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (n >= 2) {
		//DEBUGPOINT("Here\n");
		if (!lua_isnil(L, 2))
			flags = luaL_checkinteger(L, 2);
    }

	//DEBUGPOINT("Here top = %d\n", lua_gettop(L));
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);

	reqHandler->executeGenericTask(NULL, &vs_connection_new, params);

	return lua_yieldk(L, 0, (lua_KContext)"New: connection could not be established", completion_common_routine);
}

/*
 * success = connection:autocommit(on)
 */
static int connection_autocommit(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    int on = lua_toboolean(L, 2); 
    int err = 1;

    if (conn->sqlite) {
	if (on) {
	    err = rollback(conn);
        }

	conn->autocommit = on;	
    }

    lua_pushboolean(L, !err);
    return 1;
}

static void* vs_connection_autocommit(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    int n = get_num_generic_params(iparams);
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams,1);
    int on = (int)(long)((get_generic_task_bool_param(iparams,2)));

    int err = 1;
    if (conn->sqlite) {
		if (on) {
			err = rollback(conn);
		}

		conn->autocommit = on;	
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();
	int b = !err;
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_connection_autocommit(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    luaL_checktype(L, 2, LUA_TBOOLEAN); 
    int on = lua_toboolean(L, 2); 

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);

	reqHandler->executeGenericTask(NULL, &vs_connection_autocommit, params);

	return lua_yieldk(L, 0, (lua_KContext)"autocommit could not be set", completion_common_routine);
}


/*
 * success = connection:close()
 */
static int connection_close(lua_State *L)
{
	//DEBUGPOINT("Here in connection_close\n");
	connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
	int disconnect = 0;   

	if (conn->sqlite) {
		rollback(conn);
		sqlite3_close(conn->sqlite);
		disconnect = 1;
		conn->sqlite = NULL;
	}

	lua_pushboolean(L, disconnect);
	return 1;
}

static void v_nr_connection_close(void* v)
{
    connection_t *conn = (connection_t *)v;
	int disconnect = 0;

    if (conn->sqlite) {
		rollback(conn);
		sqlite3_close(conn->sqlite);
		disconnect = 1;
		conn->sqlite = NULL;
    }

	free(conn);

	return;
}

static void* vs_connection_close(void* v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams,1);
	int disconnect = 0;

    if (conn->sqlite) {
		rollback(conn);
		sqlite3_close(conn->sqlite);
		disconnect = 1;
		conn->sqlite = NULL;
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &disconnect);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_connection_close(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

    if (!(conn->sqlite)) {
		lua_pushboolean(L, 1);
		return 1;
	}

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_connection_close, params);
	return lua_yieldk(L, 0, (lua_KContext)"connection could not be closed", completion_common_routine);
}

/*
 * success = connection:commit()
 */
static int connection_commit(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    int err = 1;

    if (conn->sqlite) {
	err = commit(conn);
    }

    lua_pushboolean(L, !err);
    return 1;
}

static void* vs_connection_commit(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams,1);
	int err = 1;

    if (conn->sqlite) {
		err = commit(conn);
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();
	int b = !err;
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

/*
 * success = connection:commit()
 */
static int initiate_connection_commit(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

    if (!(conn->sqlite)) {
		lua_pushboolean(L, 1);
		return 1;
	}

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_connection_commit, params);
	return lua_yieldk(L, 0, (lua_KContext)"transaction could not be committed", completion_common_routine);
}

/*
 * ok = connection:ping()
 */
static int connection_ping(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    int ok = 0;   

    if (conn->sqlite) {
	ok = 1;
    }

    lua_pushboolean(L, ok);
    return 1;
}

/*
 * statement,err = connection:prepare(sql_str)
 */
static int connection_prepare(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

    if (conn->sqlite) {
		return db_sqlite3_statement_create(L, conn, luaL_checkstring(L, 2));
    }

    lua_pushnil(L);    
    lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
    return 2;
}

static void* vs_connection_prepare(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams,1);
	char * sql_statement = (char*)get_generic_task_ptr_param(iparams,2);

	generic_task_params_ptr_t oparams = new_generic_task_params();
	ev_sqlite3_statement_create(iparams, oparams, conn, sql_statement);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

/*
 * statement,err = connection:prepare(sql_str)
 */
static int initiate_connection_prepare(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

	if (!(conn->sqlite)) {
		lua_pushnil(L);    
		lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
		return 2;
	}

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_connection_prepare, params);
	return lua_yieldk(L, 0, (lua_KContext)"statement could not be prepared", completion_common_routine);
}

/*
 * quoted = connection:quote(str)
 */
static int connection_quote(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    size_t len;
    const char *from = luaL_checklstring(L, 2, &len);
    char *to;

    if (!conn->sqlite) {
        luaL_error(L, EV_SQL_ERR_DB_UNAVAILABLE);
    }

    to = sqlite3_mprintf("%q", from);

    lua_pushstring(L, to);
    sqlite3_free(to);

    return 1;
}

/*
 * success = connection:rollback()
 */
static int connection_rollback(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    int err = 1;

    if (conn->sqlite) {
	err =rollback(conn);
    }

    lua_pushboolean(L, !err);
    return 1;
}

static void* vs_connection_rollback(void * inp)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)inp;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams,1);
	int err = 1;
	err = rollback(conn);

	generic_task_params_ptr_t oparams = new_generic_task_params();
	int b = !err;
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_connection_rollback(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);
    if (!(conn->sqlite)) {
		lua_pushboolean(L, 1);
		return 1;
	}
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_connection_rollback, params);
	return lua_yieldk(L, 0, (lua_KContext)"transaction could not be rolled back", completion_common_routine);
}
/*
 * last_id = connection:last_id()
 */
static int connection_lastid(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

    lua_pushinteger(L, sqlite3_last_insert_rowid(conn->sqlite));
    return 1;
}

/*
 * __gc 
 */
/*
 * Not in use
 */
static int connection_gc(lua_State *L) {
    /* always close the connection */
    connection_close(L);

	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	Poco::evnet::EVServer * server = reqHandler->getServerPtr();
	server->submitRequestForTaskExecutionNR(v_hello_world, 0);

    return 0;
}

/*
 * __gc
 * in use
 */
static int new_connection_gc(lua_State *L)
{
    /* always close the connection */
    connection_t *lconn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

	connection_t *conn = (connection_t *)malloc(sizeof(connection_t));
	memcpy(conn, lconn, sizeof(connection_t));

	v_nr_connection_close(conn);
	/*
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	Poco::evnet::EVServer * server = reqHandler->getServerPtr();
	server->submitRequestForTaskExecutionNR(v_nr_connection_close, conn);
	*/

	//STACK_TRACE();

    return 0;
}

/* This does not work. */
static int v2_new_connection_gc(lua_State *L)
{
    /* always close the connection */
	return initiate_connection_close(L);
}

/*
 * __tostring
 */
static int connection_tostring(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_SQLITE_CONNECTION);

    lua_pushfstring(L, "%s: %p", EV_SQLITE_CONNECTION, conn);

    return 1;
}

extern "C" int try_begin_transaction(connection_t *conn);
int try_begin_transaction(connection_t *conn)
{
    if (conn->autocommit) {
        return 1;
    }

    return begin(conn) == 0;
}

extern "C" int ev_sqlite3_connection(lua_State *L);
int ev_sqlite3_connection(lua_State *L)
{
    /*
     * instance methods
     */
    static const luaL_Reg connection_methods[] = {
	{"autocommit", initiate_connection_autocommit}, // Done
	{"close", initiate_connection_close}, // Done
	{"commit", initiate_connection_commit}, // Done
	{"ping", connection_ping}, // Only memory operation
	{"prepare", initiate_connection_prepare}, // Done
	{"quote", connection_quote}, // Only memory operation
	{"rollback", initiate_connection_rollback}, // Done
	{"last_id", connection_lastid}, //Only memory operation
	{NULL, NULL}
    };

    /*
     * class methods
     */
    static const luaL_Reg connection_class_methods[] = {
	{"New", initiate_connection_new}, // Done
	//{"New", connection_new}, // Done
	{NULL, NULL}
    };

    ev_sql_register(L, EV_SQLITE_CONNECTION,
		 connection_methods, connection_class_methods, 
		 new_connection_gc, connection_tostring);

    /*
     * Connection flag constants exported in our namespace
     */
    static const struct {
      const char *name;
      int value;
    } sqlite3_constants[] = { 
      "SQLITE_OPEN_READONLY",     SQLITE_OPEN_READONLY,
      "SQLITE_OPEN_READWRITE",    SQLITE_OPEN_READWRITE,
      "SQLITE_OPEN_CREATE",       SQLITE_OPEN_CREATE,
#ifdef SQLITE_OPEN_URI
      "SQLITE_OPEN_URI",          SQLITE_OPEN_URI,
#endif
#ifdef SQLITE_OPEN_MEMORY
      "SQLITE_OPEN_MEMORY",       SQLITE_OPEN_MEMORY,
#endif
      "SQLITE_OPEN_NOMUTEX",      SQLITE_OPEN_NOMUTEX,
      "SQLITE_OPEN_FULLMUTEX",    SQLITE_OPEN_FULLMUTEX,
      "SQLITE_OPEN_SHAREDCACHE",  SQLITE_OPEN_SHAREDCACHE,
      "SQLITE_OPEN_PRIVATECACHE", SQLITE_OPEN_PRIVATECACHE,
      NULL, 0
    };

    int i = 0;
    while (sqlite3_constants[i].name) {
      lua_pushstring(L, sqlite3_constants[i].name);
      lua_pushinteger(L, sqlite3_constants[i].value);
      lua_rawset(L, -3);
      ++i;
    }

    return 1;    
}

