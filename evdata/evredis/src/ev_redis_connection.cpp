#include <execinfo.h>

#include "Poco/evnet/evnet_lua.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVEventNotification.h"

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
static int close_connection(lua_State * L, redis_connection_t *conn);

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
    redisOptions options = {0};
    REDIS_OPTIONS_SET_TCP(&options, ip_address, atoi(port));
	options.options |= REDIS_OPT_NOAUTOFREE;
	//redisAsyncContext *ac = redisAsyncConnect(ip_address, atoi(port));
	redisAsyncContext *ac = redisAsyncConnectWithOptions(&options);
    if (ac->err) {
        /* Let *c leak for now... */
		char str[128];
		memset(str, 0, 128);
		strncpy(str, ac->errstr, 127); 
		redisAsyncDisconnect(ac);
        luaL_error(L, "Error: %s\n", str);
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
	DEBUGPOINT("Here orig_fd = [%d]\n", conn->orig_fd);
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
	//DEBUGPOINT("conn = [%p]\n", conn);
	//if (conn) {
		//DEBUGPOINT("conn->orig_fd = [%d]\n", conn->orig_fd);
		//DEBUGPOINT("conn->ac->c.fd = [%d]\n", conn->ac->c.fd);
		//DEBUGPOINT("conn->ac->err = [%d]\n", conn->ac->err);
		//DEBUGPOINT("conn->ac->c->err = [%d]\n", conn->ac->c.err);
	//}
	if ( conn &&
		(!socket_live(conn->ac->c.fd) ||
		 (conn->orig_fd != conn->ac->c.fd) ||
		 (conn->ac->err) ||
		 (conn->ac->c.err))) {
		//DEBUGPOINT("HERE CONN NOT OK\n");
		int fd = conn->ac->c.fd;
		close_connection(L, conn);
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
				n_conn->orig_fd = p->c.fd;
				/* Swap the destructor functions for reply object,
				 * so as to be able to process the reply object in this thread
				 * and then destroy it once the data is exctacted and added to LUA state
				 */
				n_conn->free_reply_obj = n_conn->ac->c.reader->fn->coreFreeObject;
				//n_conn->ac->c.reader->fn->freeObject = dummy_free_reply;
				n_conn->ac->c.reader->fn->freeObject = NULL;
				//DEBUGPOINT("1\n");
				//DEBUGPOINT("n_conn->ac->c.reader->fn->freeObject = [%p]\n", n_conn->ac->c.reader->fn->freeObject);
				//debug_conn(n_conn);
				//DEBUGPOINT("1\n");
			}
			luaL_getmetatable(L, EV_REDIS_CONNECTION);
			lua_setmetatable(L, -2);
			//DEBUGPOINT("CONNECTION SUCCEEDED top=[%d]\n", lua_gettop(L));
			//DEBUGPOINT("Here ac = [%p]\n", n_conn->ac);

			return 1;
		}
	}
	else {
		//DEBUGPOINT("FOUND CONNECTION [%p][%p] from pool\n", conn, (void*)conn->ac);
		redis_connection_t * n_conn = (redis_connection_t *)lua_newuserdata(L, sizeof(redis_connection_t));
		{
			{
				n_conn->ac = conn->ac;
				n_conn->s_host = conn->s_host;
				n_conn->s_dbname = conn->s_dbname;
				n_conn->conn_in_error = conn->conn_in_error;
				n_conn->free_reply_obj = conn->free_reply_obj;
				n_conn->orig_fd = conn->orig_fd;
				/* Reassigning the dummy_free_reply because, change of lua_State
				 * removes the loaded .so thus the old function pointer
				 * is stale. It needs to be reassigned to the latest dummy function pointer.
				 */
				n_conn->ac->c.reader->fn->freeObject = NULL;
				//DEBUGPOINT("2\n");
				//debug_conn(n_conn);
				//DEBUGPOINT("2\n");
			}
		}
		free(conn);

		luaL_getmetatable(L, EV_REDIS_CONNECTION);
		lua_setmetatable(L, -2);

		return 1;
	}
}

static int close_connection(lua_State *L, redis_connection_t *conn)
{
    int disconnect = 0;   
    if (conn->ac) {
		//DEBUGPOINT("Here conn->ac = [%p]\n", conn->ac);
		Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		reqHandler->redisDisconnect(NULL, conn->ac);
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

	//DEBUGPOINT("CLOSING CONNECTION [%p][%p]\n", conn, conn->ac);
	int disconnect = close_connection(L, conn);
    lua_pushboolean(L, disconnect);
    return 1;
}


static int repurpose_connection(lua_State *L)
{
    redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
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
			n_conn->orig_fd = conn->orig_fd;
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

static int push_element(lua_State *L, redisReply *reply)
{
	switch (reply->type) {
		case REDIS_REPLY_NIL:
			lua_pushnil(L);
			break;
		case REDIS_REPLY_STRING:
			{
				char * out_str = strndup(reply->str, reply->len);
				lua_pushstring(L, out_str);
				free(out_str);
			}
			break;
		case REDIS_REPLY_STATUS:
			{
				char * out_str = strndup(reply->str, reply->len);
				lua_pushstring(L, out_str);
				free(out_str);
			}
			break;
		case REDIS_REPLY_INTEGER:
			lua_pushinteger(L, reply->integer);
			break;
		case REDIS_REPLY_BOOL:
			lua_pushboolean(L, reply->integer);
			break;
		case REDIS_REPLY_DOUBLE:
			lua_pushnumber(L, reply->dval);
			break;
		default:
		{
			char err[512] = {0};
			sprintf(err, "[%s:%d] Support for reply type [%d] not yet implemented\n", __FILE__, __LINE__, reply->type);
			luaL_error(L, err);
			return 0;
		}
	}
	return 1;
}

static int transceive_complete(lua_State *L, int status, lua_KContext ctx)
{
	//DEBUGPOINT("Here\n");
	redis_connection_t *conn = (redis_connection_t *)ctx;
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVEventNotification &usN = reqHandler->getUNotification();
	//DEBUGPOINT("Here\n");
	//
	redisReply * reply = (redisReply*)usN.getTaskReturnValue();
	usN.setTaskReturnValue(NULL); // So that usN destructor will not free task_return_value
	if (conn->ac->err || conn->ac->c.err) {
		DEBUGPOINT("Here DEFENSIVE CODE\n");
		conn->conn_in_error = 1;
		if (reply) conn->free_reply_obj(reply);
		luaL_error(L, "Error occured in transceive of redis command\n");
		return 0;
	}


	if (reply->type != REDIS_REPLY_ERROR) {
		//DEBUGPOINT("Here\n");
		lua_pushboolean(L, 1);
		switch (reply->type) {
			case REDIS_REPLY_NIL:
				lua_pushnil(L);
				break;
			case REDIS_REPLY_STRING:
				{
					char * out_str = strndup(reply->str, reply->len);
					lua_pushstring(L, out_str);
					free(out_str);
				}
				break;
			case REDIS_REPLY_STATUS:
				{
					char * out_str = strndup(reply->str, reply->len);
					lua_pushstring(L, out_str);
					free(out_str);
				}
				break;
			case REDIS_REPLY_INTEGER:
				lua_pushinteger(L, reply->integer);
				break;
			case REDIS_REPLY_BOOL:
				lua_pushboolean(L, reply->integer);
				break;
			case REDIS_REPLY_DOUBLE:
				lua_pushnumber(L, reply->dval);
				break;
			case REDIS_REPLY_ARRAY:
			{
				redisReply *array_element = NULL;
				if (reply->elements > 0 && reply->element == NULL) {
					conn->free_reply_obj(reply);
					luaL_error(L, "[%s:%d] Impossible condition", __FILE__, __LINE__);
					return 0;
				}
				lua_newtable(L);
				for (int i = 0; i < reply->elements; i++) {
					array_element = reply->element[i];
					if (!push_element(L, array_element)) {
						char err[512] = {0};
						sprintf(err, "Support for reply type [%d] not yet implemented\n", array_element->type);
						conn->free_reply_obj(reply);
						luaL_error(L, err);
						return 0;
					}
					lua_seti(L, -2, (i+1));
				}
				break;
			}
			default:
			{
				char err[512] = {0};
				sprintf(err, "[%s:%d] Support for reply type [%d] not yet implemented\n", __FILE__, __LINE__, reply->type);
				conn->free_reply_obj(reply);
				luaL_error(L, err);
				return 0;
			}
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
	//DEBUGPOINT("Here [%p]\n", conn->free_reply_obj);
	//DEBUGPOINT("3\n");
	//debug_conn(conn);
	//DEBUGPOINT("3\n");
	conn->free_reply_obj(reply);
	//DEBUGPOINT("Here\n");
	return 3;
}

/*
 * response = connection:transceive(command)
 */
static int transceive(lua_State *L)
{
	redis_connection_t *conn = (redis_connection_t *)luaL_checkudata(L, 1, EV_REDIS_CONNECTION);
	int ok = 0;   

	//DEBUGPOINT("Here\n");
	if (conn->ac) {
		int status = socket_live(conn->ac->c.fd);
		//DEBUGPOINT("Here status=[%d] ac = [%p]\n", status, conn->ac);

		if (!status || conn->ac->err || conn->ac->c.err) {
			//DEBUGPOINT("Here\n");
			conn->conn_in_error = 1;
			luaL_error(L, "Socket connection to redis server [%d] not live\n", conn->ac->c.fd);
			return 0;
		}
	}
	const char * message = luaL_checkstring(L, 2);

	//DEBUGPOINT("Here\n");
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	//DEBUGPOINT("Here [%s]\n", message);
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

