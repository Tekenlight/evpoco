#include "Poco/evdata/evsqlite/ev_sqlite3.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

extern "C" {
int ev_sqlite3_statement_create(lua_State *L, connection_t *conn, const char *sql_query);
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
static void* connection_new(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    int n = iparams->n;

    const char *db = NULL;
    connection_t *conn = NULL;

    /* db */
    switch(n) {
    default:
		/*
		 * db is the only mandatory parameter
		 */
		db = (char*)get_generic_task_param(iparams, 1);
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (n >= 2) {
		void *p =  get_generic_task_param(iparams, 2);
		if (p) flags = (int)(long)(p);
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();

    conn = (connection_t *)malloc(sizeof(connection_t));
    if (sqlite3_open_v2(db, &conn->sqlite, flags, NULL) != SQLITE_OK) {
		free(conn);
		set_lua_stack_out_param(oparams, 1, EV_LUA_TNIL, 0);
		char str[1024];
		sprintf(str, EV_SQL_ERR_CONNECTION_FAILED, sqlite3_errmsg(conn->sqlite));
		set_lua_stack_out_param(oparams, 2, EV_LUA_TSTRING, &str);
		return (void*)oparams;
    }

    conn->autocommit = 0;

	gen_lua_user_data_t* gud = new gen_lua_user_data_t();
    gud->meta_table_name = strdup(EV_SQLITE_CONNECTION);
	gud->user_data = conn;
	gud->size = sizeof(connection_t);
	set_lua_stack_out_param(oparams, 1, EV_LUA_TUSERDATA, &gud);

	iparams = destroy_generic_task_in_params(iparams);
    return (void*)oparams;
}

static int complete_connection_new(lua_State* L, int status, lua_KContext ctx)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() != 0) {
		luaL_error(L, "New: connection could not be established");
		return 0;
	}
	generic_task_params_ptr_t oparams = (generic_task_params_ptr_t)(usN.getTaskReturnValue());
	push_out_params_to_lua_stack(oparams, L);
	int n = oparams->n;

	oparams = destroy_generic_task_out_params(oparams);
	return n;
}

static int initiate_connection_new(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
    int n = lua_gettop(L);

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
		if (!lua_isnil(L, 2))
			flags = luaL_checkinteger(L, 2);
    }

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);

	reqHandler->executeGenericTask(NULL, &connection_new, params);

	return lua_yieldk(L, 0, (lua_KContext)0, complete_connection_new);
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


/*
 * success = connection:close()
 */
static int connection_close(lua_State *L)
{
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
	return ev_sqlite3_statement_create(L, conn, luaL_checkstring(L, 2));
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
static int connection_gc(lua_State *L)
{
    /* always close the connection */
    connection_close(L);

    return 0;
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
	{"autocommit", connection_autocommit},
	{"close", connection_close},
	{"commit", connection_commit},
	{"ping", connection_ping},
	{"prepare", connection_prepare},
	{"quote", connection_quote}, // Only memory operation
	{"rollback", connection_rollback}, 
	{"last_id", connection_lastid}, //Only memory operation
	{NULL, NULL}
    };

    /*
     * class methods
     */
    static const luaL_Reg connection_class_methods[] = {
	{"New", initiate_connection_new}, // Opens the database needs to be async
	{NULL, NULL}
    };

    ev_sql_register(L, EV_SQLITE_CONNECTION,
		 connection_methods, connection_class_methods, 
		 connection_gc, connection_tostring);

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

