#include <execinfo.h>

#include "Poco/evnet/evnet_lua.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evdata/evredis/ev_redis.h"


int socket_live(int fd);
void init_pool_type(const char * db_type, Poco::evnet::evl_pool::queue_holder *qhf);
void * get_conn_from_pool(const char * db_type, const char * host, const char * dbname);
void add_conn_to_pool(const char * db_type, const char * host, const char * dbname, void * conn);

static redisAsyncContext * initiate_connection(const char * host, const char * dbname,  const char * user, const char* password);
static int open_connection_finalize(lua_State *L, int status, lua_KContext ctx);
static int open_connection_initiate(lua_State *L);
static int repurpose_connection(lua_State *L);
static int connection_gc(lua_State *L);
static int connection_tostring(lua_State *L);
static int orchestrate_connection_process(lua_State *L, int step_to_continue);
static int orig_connection_close(lua_State *L);
static int close_connection(redis_connection_t *conn);

static void dummy_free_reply(void * p)
{
	//DEBUGPOINT("dummy_free_reply\n");
	return;
}
/*
 * instance methods
 * Ultimately results in a writeable and readable connection
 */
//void EVTCPServer::redisLibevAttach(redisAsyncContext *ac, redisLibevAttach_funcptr fptr)
static redisAsyncContext * initiate_connection(lua_State *L, const char * ip_address, const char * port, const char * dbname,  const char * user, const char* password)
{
	redisAsyncContext *ac = redisAsyncConnect(ip_address, atoi(port));
    if (ac->err) {
        /* Let *c leak for now... */
        luaL_error(L, "Error: %s\n", ac->errstr);
        return NULL;
    }

	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	reqHandler->getServer().redisLibevAttach(ac);

	return ac;
}

static void debug_conn(redis_connection_t *conn)
{
	DEBUGPOINT("Here conn = [%p]\n", (void*)conn);
	DEBUGPOINT("Here ac = [%p]\n", (void*)conn->ac);
	DEBUGPOINT("Here ac->c = [%p]\n", (void*)&conn->ac->c);
	DEBUGPOINT("Here ac->c.funcs = [%p]\n", (void*)conn->ac->c.funcs);
	DEBUGPOINT("Here ac->c.funcs->async_write = [%p]\n", (void*)conn->ac->c.funcs->async_write);
	DEBUGPOINT("Here ac->c.funcs->async_read = [%p]\n", (void*)conn->ac->c.funcs->async_read);
	DEBUGPOINT("Here s_host = [%s]\n", conn->s_host->c_str());
	DEBUGPOINT("Here s_dbname = [%s]\n", conn->s_dbname->c_str());
	DEBUGPOINT("Here conn_in_error = [%d]\n", conn->conn_in_error);
	DEBUGPOINT("Here free_reply_obj = [%p]\n", (void*)conn->free_reply_obj);
	return;
}

static int lua_debug_conn(lua_State *L)
{
	redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
	debug_conn(conn);
	return 0;
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
	redis_connection_t * conn = (redis_connection_t *) get_conn_from_pool(REDIS_DB_TYPE_NAME, host, dbname);
	if ( conn && !socket_live(conn->ac->c.fd)) {
		int fd = conn->ac->c.fd;
		close_connection(conn);
		free(conn);
		conn = NULL;
	}

	//DEBUGPOINT("CONN = [%p]\n", conn);
	if (conn == NULL) {
		//DEBUGPOINT("DID NOT FIND CONNECTION from pool\n");
		redisAsyncContext * p = initiate_connection(L, host, port, dbname, user, password);
		if (!p) {
			return 0;
		}
		else {
			redis_connection_t * n_conn = (redis_connection_t *)lua_newuserdata(L, sizeof(redis_connection_t));
			memset(n_conn, 0, sizeof(redis_connection_t));
			{
				n_conn->ac = p;
				n_conn->s_host = new std::string(host);
				n_conn->s_dbname = new std::string(dbname);
				n_conn->conn_in_error = 0;
				/* Swap the destructor functions for reply object,
				 * so as to be able to process the reply object in this thread
				 * and then destroy it once the data is exctacted and added to LUA state
				 */
				n_conn->free_reply_obj = n_conn->ac->c.reader->fn->freeObject;
				n_conn->ac->c.reader->fn->freeObject = dummy_free_reply;
			}
			luaL_getmetatable(L, EV_REDIS_CONNECTION);
			lua_setmetatable(L, -2);
			//DEBUGPOINT("CONNECTION SUCCEEDED top=[%d]\n", lua_gettop(L));
			//DEBUGPOINT("Here ac = [%p]\n", n_conn->ac);

			return 1;
		}
	}
	else {
		//DEBUGPOINT("FOUND CONNECTION [%p][%p] from pool\n", conn, (void*)conn->pg_conn);
		redis_connection_t * n_conn = (redis_connection_t *)lua_newuserdata(L, sizeof(redis_connection_t));
		{
			{
				n_conn->ac = conn->ac;
				n_conn->s_host = conn->s_host;
				n_conn->s_dbname = conn->s_dbname;
				n_conn->conn_in_error = conn->conn_in_error;
				n_conn->free_reply_obj = conn->free_reply_obj;
				/* Reassigning the dummy_free_reply because, change of lua_State
				 * removes the loaded .so thus the old function pointer
				 * is stale. It needs to be reassigned to the latest dummy function pointer.
				 */
				n_conn->ac->c.reader->fn->freeObject = dummy_free_reply;
			}
		}
		free(conn);

		luaL_getmetatable(L, EV_REDIS_CONNECTION);
		lua_setmetatable(L, -2);

		return 1;
	}
}

static int close_connection(redis_connection_t *conn)
{
    int disconnect = 0;   
    if (conn->ac) {
		redisAsyncFree(conn->ac);
		disconnect = 1;
		conn->ac = NULL;
    }

	delete conn->s_host;
	delete conn->s_dbname;

	return disconnect;
}

static int orig_connection_close(lua_State *L)
{
    redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);

	DEBUGPOINT("CLOSING CONNECTION [%p][%p]\n", conn, conn->ac);
	int disconnect = close_connection(conn);
    lua_pushboolean(L, disconnect);
    return 1;
}


static int repurpose_connection(lua_State *L)
{
    redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
	//socket_live(PQsocket(conn->pg_conn));
	if (conn->conn_in_error == 1) {
		return orig_connection_close(L);
	}
	else {
		redis_connection_t *n_conn = (redis_connection_t *)malloc(sizeof(redis_connection_t));
		{
			n_conn->ac = conn->ac;
			n_conn->s_host = conn->s_host;
			n_conn->s_dbname = conn->s_dbname;
			n_conn->conn_in_error = conn->conn_in_error;
			n_conn->free_reply_obj = conn->free_reply_obj;
		}
		add_conn_to_pool(REDIS_DB_TYPE_NAME, n_conn->s_host->c_str(), n_conn->s_dbname->c_str(), n_conn);
	}
	return 0;
}

static int connection_gc(lua_State *L)
{
	//DEBUGPOINT("Here in GC\n");
	int ret =  repurpose_connection(L);
	return ret;
}

static int connection_tostring(lua_State *L)
{
    void *conn = (void *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
    lua_pushfstring(L, "%s:%p", EV_REDIS_CONNECTION, conn);

    return 1;
}

/*
 * ok = connection:ping()
 */
static int connection_ping(lua_State *L)
{
	redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
	int ok = 0;   

	if (conn->ac) {
		int status = socket_live(conn->ac->c.fd);

		if (status)
			ok = 1;
	}

	lua_pushboolean(L, ok);
	return 1;
}

static int transceive_complete(lua_State *L, int status, lua_KContext ctx)
{
	redis_connection_t *conn = (redis_connection_t *)ctx;
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();

	redisReply * reply = (redisReply*)usN.getTaskReturnValue();
	usN.setTaskReturnValue(NULL); // So that usN destructor will not free task_return_value

	if (reply->type != REDIS_REPLY_ERROR) {
		if ((reply->type != REDIS_REPLY_NIL) && (reply->type != REDIS_REPLY_STRING) && (reply->type != REDIS_REPLY_STATUS)) {
			conn->free_reply_obj(reply);
			luaL_error(L, "Support for reply type [%d] not yet implemented\n", reply->type);
			return 0;
		}

		lua_pushboolean(L, 1);
		if (reply->str) {
			char * out_str = strndup(reply->str, reply->len);
			lua_pushstring(L, out_str);
			free(out_str);

		}
		else {
			lua_pushnil(L);
		}
		lua_pushnil(L);
	}
	else {
		lua_pushboolean(L, 0);
		lua_pushnil(L);
		char * out_str = strndup(reply->str, reply->len);
		lua_pushstring(L, reply->str);
		free(out_str);
	}
	conn->free_reply_obj(reply);
	return 3;
}

/*
 * response = connection:transceive(command)
 */
static int transceive(lua_State *L)
{
	redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
	int ok = 0;   

	if (conn->ac) {
		int status = socket_live(conn->ac->c.fd);

		if (!status) {
			conn->conn_in_error = 1;
			luaL_error(L, "Socket connection to redis server [%d] not live\n", conn->ac->c.fd);
			return 0;
		}
	}
	const char * message = luaL_checkstring(L, 2);

	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	reqHandler->redistransceive(NULL, conn->ac, message);
	return lua_yieldk(L, 0, (lua_KContext)conn, transceive_complete);
}

static int ev_redis_connection(lua_State *L)
{
	redis_queue_holder qhf;
	static int db_initialized = 0;
	static const luaL_Reg connection_methods[] = {
		{"__gc", connection_gc},
		{"__tostring", connection_tostring},
		{"close", orig_connection_close},
		{"ping", connection_ping},
		{"transceive", transceive},
		{"debug_conn", lua_debug_conn},
		{NULL, NULL}
	};

	static const luaL_Reg connection_class_methods[] = {
		{"new", open_connection_initiate},
		{NULL, NULL}
	};

	int n = lua_gettop(L);
	luaL_newmetatable(L, EV_REDIS_CONNECTION);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	luaL_setfuncs(L, connection_methods, 0);
	lua_settop(L, n);

	lua_newtable(L);
	luaL_setfuncs(L, connection_class_methods, 0);

	if (!db_initialized) init_pool_type(REDIS_DB_TYPE_NAME, &qhf);
	db_initialized = 1;

	return 1;    
}


extern "C" int luaopen_evredis(lua_State *L);
int luaopen_evredis(lua_State *L)
{
    return ev_redis_connection(L);
}

