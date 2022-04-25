#include "Poco/evdata/evmysql/ev_mysql.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

#include <execinfo.h>

extern "C"
{
    void ev_mysql_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams,
                                   connection_t *conn, const char *sql_query);
    int completion_common_routine(lua_State *L, int status, lua_KContext ctx);
    gen_lua_user_data_t *get_generic_lua_userdata(const char *name, void *data, size_t size);
}

extern "C" lua_State *getL(generic_task_params_ptr_t p);

static void *vs_connection_new(void *v)
{
	//DEBUGPOINT("ENTER vs_connection_new\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    int n = get_num_generic_params(iparams);

    connection_t *conn = NULL;

    const char *host = NULL;
    const char *user = NULL;
    const char *password = NULL;
    const char *db = NULL;
    int port = 0;

    const char *unix_socket = NULL;
    int client_flag = 0; /* TODO always 0, set flags from options table */

    /* db, user, password, host, port */
    switch (n)
    {
    case 5:
    {
        void *p5 = get_generic_task_ptr_param(iparams, 5);
        if (p5)
            port = (int)(long)(p5);
        // fallthrough
    }
    case 4:
    {
        void *p4 = get_generic_task_ptr_param(iparams, 4);
        if (p4)
            host = (char *)p4;
        if (host != NULL)
        {
            if (host[0] == '/')
            {
                unix_socket = host;
                host = NULL;
            };
        };
        // fallthrough
    }
    case 3:
    {
        void *p3 = get_generic_task_ptr_param(iparams, 3);
        if (p3)
            password = (char *)p3;
        // fallthrough
    }
    case 2:
    {
        void *p2 = get_generic_task_ptr_param(iparams, 2);
        if (p2)
            user = (char *)p2;
        // fallthrough
    }
    case 1:
    {
        /*
         * db is the only mandatory parameter
         */
        db = (char *)get_generic_task_ptr_param(iparams, 1);
        // fallthrough
    }
    }

    generic_task_params_ptr_t oparams = new_generic_task_params();

    conn = (connection_t *)malloc(sizeof(connection_t));
    memset(conn, 0, sizeof(connection_t));

    conn->mysql = mysql_init(NULL);

    if (!mysql_real_connect(conn->mysql, host, user, password, db, port, unix_socket, client_flag))
    {
        set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
        char str[1024];
        sprintf(str, EV_SQL_ERR_CONNECTION_FAILED, mysql_error(conn->mysql));
        set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
        mysql_close(conn->mysql);
        free(conn);
        return (void *)oparams;
    }

    /*
     * by default turn off autocommit
     */
    mysql_autocommit(conn->mysql, 0);

    set_lua_stack_out_param(oparams, EV_LUA_TUSERDATA,
                            get_generic_lua_userdata(EV_MYSQL_CONNECTION, conn, sizeof(connection_t)));

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_new\n");
    return (void *)oparams;
}

/*
 * connection,err = EV.MySQl.New(dbname, user, password, host, port)
 */
static int initiate_connection_new(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    int n = lua_gettop(L);

    const char *host = NULL;
    const char *user = NULL;
    const char *password = NULL;
    const char *db = NULL;
    int port = 0;

    const char *unix_socket = NULL;

    /* db, user, password, host, port */
    switch (n)
    {
    case 5:
        if (lua_isnil(L, 5) == 0)
            port = luaL_checkinteger(L, 5);
    // fallthrough
    case 4:
        if (lua_isnil(L, 4) == 0)
            host = luaL_checkstring(L, 4);
        if (host != NULL)
        {
            if (host[0] == '/')
            {
                unix_socket = host;
                host = NULL;
            };
        };
    // fallthrough
    case 3:
        if (lua_isnil(L, 3) == 0)
            password = luaL_checkstring(L, 3);
    // fallthrough
    case 2:
        if (lua_isnil(L, 2) == 0)
            user = luaL_checkstring(L, 2);
    // fallthrough
    case 1:
        /*
         * db is the only mandatory parameter
         */
        db = luaL_checkstring(L, 1);
        // fallthrough
    }

    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);

    reqHandler->executeGenericTask(NULL, &vs_connection_new, params);

    return lua_yieldk(L, 0, (lua_KContext) "New: connection could not be established", completion_common_routine);
}

static void *vs_connection_autocommit(void *v)
{
	//DEBUGPOINT("ENTER vs_connection_autocommit\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    int n = get_num_generic_params(iparams);
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams, 1);
    int on = (int)(long)((get_generic_task_bool_param(iparams, 2)));

    int err = 0;
    if (conn->mysql)
    {
        err = mysql_autocommit(conn->mysql, on);
    }

    generic_task_params_ptr_t oparams = new_generic_task_params();
    int b = !err;
    set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_autocommit\n");
    return oparams;
}

/*
 * success = connection:autocommit(on)
 */
static int initiate_connection_autocommit(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);
    luaL_checktype(L, 2, LUA_TBOOLEAN);
    int on = lua_toboolean(L, 2);

    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);

    reqHandler->executeGenericTask(NULL, &vs_connection_autocommit, params);

    return lua_yieldk(L, 0, (lua_KContext) "autocommit could not be set", completion_common_routine);
}

static void v_nr_connection_close(void *v)
{
    connection_t *conn = (connection_t *)v;
    int disconnect = 0;

    if (conn->mysql)
    {
        mysql_close(conn->mysql);
        disconnect = 1;
        conn->mysql = NULL;
    }

    free(conn);

    return;
}

static void *vs_connection_close(void *v)
{
	//DEBUGPOINT("ENTER vs_connection_close\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams, 1);
    int disconnect = 0;

    if (conn->mysql)
    {
        mysql_close(conn->mysql);
        disconnect = 1;
        conn->mysql = NULL;
    }

    generic_task_params_ptr_t oparams = new_generic_task_params();
    set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &disconnect);

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_close\n");
    return oparams;
}

/*
 * success = connection:close()
 */
static int initiate_connection_close(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    if (!(conn->mysql))
    {
        lua_pushboolean(L, 1);
        return 1;
    }

    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
    reqHandler->executeGenericTask(NULL, &vs_connection_close, params);
    return lua_yieldk(L, 0, (lua_KContext) "connection could not be closed", completion_common_routine);
}

static void *vs_connection_commit(void *v)
{
	//DEBUGPOINT("ENTER vs_connection_commit\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams, 1);
    int err = 0;

    if (conn->mysql)
    {
        err = mysql_commit(conn->mysql);
    }

    generic_task_params_ptr_t oparams = new_generic_task_params();
    int b = !err;
    set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_commit\n");
    return oparams;
}

/*
 * success = connection:commit()
 */
static int initiate_connection_commit(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    if (!(conn->mysql))
    {
        lua_pushboolean(L, 1);
        return 1;
    }

    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
    reqHandler->executeGenericTask(NULL, &vs_connection_commit, params);
    return lua_yieldk(L, 0, (lua_KContext) "transaction could not be committed", completion_common_routine);
}

/*
 * ok = connection:ping()
 */
static int connection_ping(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);
    int err = 1;

    if (conn->mysql)
    {
        err = mysql_ping(conn->mysql);
    }

    lua_pushboolean(L, !err);
    return 1;
}

static void *vs_connection_prepare(void *v)
{
	//DEBUGPOINT("ENTER vs_connection_prepare\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams, 1);
    char *sql_statement = (char *)get_generic_task_ptr_param(iparams, 2);

    generic_task_params_ptr_t oparams = new_generic_task_params();
    ev_mysql_statement_create(iparams, oparams, conn, sql_statement);

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_prepare\n");
    return oparams;
}

/*
 * statement,err = connection:prepare(sql_string)
 */
static int initiate_connection_prepare(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    if (!(conn->mysql))
    {
        lua_pushnil(L);
        lua_pushstring(L, EV_SQL_ERR_DB_UNAVAILABLE);
        return 2;
    }

    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
    reqHandler->executeGenericTask(NULL, &vs_connection_prepare, params);
    return lua_yieldk(L, 0, (lua_KContext) "statement could not be prepared", completion_common_routine);
}

/*
 * quoted = connection:quote(str)
 */
static int connection_quote(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);
    size_t len;
    const char *from = luaL_checklstring(L, 2, &len);
    char *to = (char *)calloc(len * 2 + 1, sizeof(char));
    int quoted_len;

    if (!conn->mysql)
    {
        luaL_error(L, EV_SQL_ERR_DB_UNAVAILABLE);
    }

    quoted_len = mysql_real_escape_string(conn->mysql, to, from, len);

    lua_pushlstring(L, to, quoted_len);
    free(to);

    return 1;
}

static void *vs_connection_rollback(void *inp)
{
	//DEBUGPOINT("ENTER vs_connection_rollback\n");
    generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)inp;
    connection_t *conn = (connection_t *)get_generic_task_ptr_param(iparams, 1);
    int err = 0;
    err = mysql_rollback(conn->mysql);

    generic_task_params_ptr_t oparams = new_generic_task_params();
    int b = !err;
    set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &b);

    iparams = destroy_generic_task_in_params(iparams);

	//DEBUGPOINT("EXIT vs_connection_rollback\n");
    return oparams;
}

/*
 * success = connection:rollback()
 */
static int initiate_connection_rollback(lua_State *L)
{
    Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
    poco_assert(reqHandler != NULL);
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);
    if (!(conn->mysql))
    {
        lua_pushboolean(L, 1);
        return 1;
    }
    generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
    reqHandler->executeGenericTask(NULL, &vs_connection_rollback, params);
    return lua_yieldk(L, 0, (lua_KContext) "transaction could not be rolled back", completion_common_routine);
}

/*
 * last_id = statement:last_id()
 */
static int connection_lastid(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    lua_pushinteger(L, mysql_insert_id(conn->mysql));
    return 1;
}

/*
 * __gc
 */
static int new_connection_gc(lua_State *L)
{
    /* always close the connection */
    connection_t *lconn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    connection_t *conn = (connection_t *)malloc(sizeof(connection_t));
    memcpy(conn, lconn, sizeof(connection_t));

    v_nr_connection_close(conn);

    return 0;
}

/*
 * __tostring
 */
static int connection_tostring(lua_State *L)
{
    connection_t *conn = (connection_t *)luaL_checkudata(L, 1, EV_MYSQL_CONNECTION);

    lua_pushfstring(L, "%s: %p", EV_MYSQL_CONNECTION, conn);

    return 1;
}

extern "C" int ev_mysql_connection(lua_State *L);
int ev_mysql_connection(lua_State *L)
{
    /*
     * instance methods
     */
    static const luaL_Reg connection_methods[] = {
        {"autocommit", initiate_connection_autocommit}, // Done
        {"close", initiate_connection_close},           // Done
        {"commit", initiate_connection_commit},         // Done
        {"ping", connection_ping},                      // Done
        {"prepare", initiate_connection_prepare},       // Done
        {"quote", connection_quote},                    // Done
        {"rollback", initiate_connection_rollback},     // Done
        {"last_id", connection_lastid},                 // Done
        {NULL, NULL}};

    static const luaL_Reg connection_class_methods[] = {
        {"New", initiate_connection_new}, // Done
        {NULL, NULL}};

    ev_sql_register(L, EV_MYSQL_CONNECTION,
                    connection_methods, connection_class_methods,
                    new_connection_gc, connection_tostring); // Done

    return 1;
}
