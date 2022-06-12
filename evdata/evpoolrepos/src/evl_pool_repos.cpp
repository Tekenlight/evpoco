extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}
#include "Poco/evnet/EVLHTTPRequestHandler.h"

#include <iostream>
#include <map>

extern void add_conn_to_pool(const char * type, const char * name, void * conn);
extern void * get_conn_from_pool(const char * type, const char * name);

const static char *_stream_socket_type_name = "streamsocket";

#define SOCKET_POOL "socket_conn_pool"

void init_pool_type(const char * db_type, Poco::evnet::evl_pool::queue_holder *qhf);

class sock_queue_holder : public Poco::evnet::evl_pool::queue_holder {
	public:
	virtual Poco::evnet::evl_pool::queue_holder* clone()
	{
		return (Poco::evnet::evl_pool::queue_holder*)(new sock_queue_holder());
	}
	virtual ~sock_queue_holder() {
		Poco::Net::StreamSocket * conn = (Poco::Net::StreamSocket*)dequeue(_queue);
		while (conn) {
			delete conn;
		}
		wf_destroy_ev_queue(_queue);
	}
};

static int add_to_pool(lua_State* L)
{
	const char *poolname = *(const char**)luaL_checkudata(L, 1, SOCKET_POOL);
	const char *name = luaL_checkstring(L, 2);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 3, _stream_socket_type_name);
	add_conn_to_pool(poolname, name, ss_ptr);
	return 0;
}

static int get_from_pool(lua_State* L)
{
	const char *poolname = *(const char**)luaL_checkudata(L, 1, SOCKET_POOL);
	const char *name = luaL_checkstring(L, 2);
	Poco::Net::StreamSocket * ss_ptr =  (Poco::Net::StreamSocket*)get_conn_from_pool(poolname, name);

	if (NULL != ss_ptr)
		lua_pushlightuserdata(L, ss_ptr);
	else
		lua_pushnil(L);

	return 1;
}

static std::map<std::string, char*> sg_initialized_pools;
static int create_pool(lua_State* L)
{
	const char *poolname = luaL_checkstring(L, 1);
	auto it = sg_initialized_pools.find(poolname);
	if (sg_initialized_pools.end() == it) {
		sock_queue_holder qhf;
		init_pool_type(poolname, &qhf);

		char ** pool_name_ptr = (char **)lua_newuserdata(L, sizeof(char *));
		char * pool_name = strdup(poolname);
		*pool_name_ptr = pool_name;
		sg_initialized_pools[std::string(poolname)] = pool_name;
	}
	else {
		char * pool_name = it->second;
		lua_pushlightuserdata(L, pool_name);
	}
	luaL_getmetatable(L, SOCKET_POOL);
	lua_setmetatable(L, -2);

	return 1;
}

static int pool_gc(lua_State *L)
{
	/* always free the handle */
    char *str = *(char **)luaL_checkudata(L, 1, SOCKET_POOL);
	//free(str);

	return 0;
}

/*
 * __tostring
 */
static int pool_tostring(lua_State *L)
{
    char *str = *(char **)luaL_checkudata(L, 1, SOCKET_POOL);
    lua_pushfstring(L, "%s", str);
    return 1;
}

extern "C" int luaopen_libevpoolrepos(lua_State *L);
int luaopen_libevpoolrepos(lua_State *L)
{
	static const luaL_Reg lua_pool_methods[] = {
		{"__gc", pool_gc},
		{"__tostring", pool_tostring},
		{ "add_to_pool", add_to_pool},
		{ "get_from_pool", get_from_pool},
		{NULL, NULL}
	};

	int n = lua_gettop(L);
	luaL_newmetatable(L, SOCKET_POOL);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	luaL_setfuncs(L, lua_pool_methods, 0);
	lua_settop(L, n);

	static const luaL_Reg repos_methods[] = {
		{"new", create_pool},
		{NULL, NULL}
	};

	lua_newtable(L);
	luaL_setfuncs(L, repos_methods, 0);

	return 1;    
}

