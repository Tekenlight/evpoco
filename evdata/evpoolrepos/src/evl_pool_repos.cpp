extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <ev_spin_lock.h>
}
#include "Poco/evnet/EVLHTTPRequestHandler.h"

#include <iostream>
#include <map>

extern void add_conn_to_pool(const char * type, const char * name, void * conn);
extern void * get_conn_from_pool(const char * type, const char * name);

const static char *_stream_socket_type_name = "streamsocket";

#define SOCKET_POOL "socket_conn_pool"

struct pool_s {
	spin_lock_p_type lock;
	const char * poolname;
};

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

static void add_to_pool(Poco::Net::StreamSocket * ss_ptr, const char *poolname, const char *name)
{
	if (ss_ptr->impl()->sockfd() == POCO_INVALID_SOCKET) {
		//DEBUGPOINT("SOCKET HAS BECOME INVALID\n");
		return;
	}

	Poco::Net::StreamSocket * n_ss_ptr = new Poco::Net::StreamSocket();
	*n_ss_ptr = *ss_ptr;
	//DEBUGPOINT("[%p] added to pool\n", n_ss_ptr);
	add_conn_to_pool(poolname, name, n_ss_ptr);

	return;
}

static int interface_add_to_pool(lua_State* L)
{
	struct pool_s * pool_ptr = (struct pool_s *)luaL_checkudata(L, 1, SOCKET_POOL);
	const char *poolname = pool_ptr->poolname;

	const char *name = luaL_checkstring(L, 2);

	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 3, _stream_socket_type_name);

	add_to_pool(ss_ptr, poolname, name);

	return 0;
}

static int share_from_pool(lua_State* L)
{
	struct pool_s * pool_ptr = (struct pool_s *)luaL_checkudata(L, 1, SOCKET_POOL);
	const char *poolname = pool_ptr->poolname;

	const char *name = luaL_checkstring(L, 2);

	while (true) {
		ev_spin_lock(pool_ptr->lock);
		Poco::Net::StreamSocket * ss_ptr =  (Poco::Net::StreamSocket*)get_conn_from_pool(poolname, name);
		if (NULL != ss_ptr) {
			if (ss_ptr->impl()->sockfd() == POCO_INVALID_SOCKET) {
				//DEBUGPOINT("SOCKET HAS BECOME INVALID\n");
				delete ss_ptr;
				ev_spin_unlock(pool_ptr->lock);
				continue;
			}
			void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
			*(Poco::Net::StreamSocket**)ptr = ss_ptr;
			//DEBUGPOINT("[%p] got from pool\n", ss_ptr);
			luaL_setmetatable(L, _stream_socket_type_name);
			add_to_pool(ss_ptr, poolname, name);

			ev_spin_unlock(pool_ptr->lock);
			break;
		}
		else {
			lua_pushnil(L);

			ev_spin_unlock(pool_ptr->lock);
			break;
		}
	}

	return 1;
}

static int get_from_pool(lua_State* L)
{
	struct pool_s * pool_ptr = (struct pool_s *)luaL_checkudata(L, 1, SOCKET_POOL);
	const char *poolname = pool_ptr->poolname;

	const char *name = luaL_checkstring(L, 2);

	while (true) {
		Poco::Net::StreamSocket * ss_ptr =  (Poco::Net::StreamSocket*)get_conn_from_pool(poolname, name);
		if (NULL != ss_ptr) {
			if (ss_ptr->impl()->sockfd() == POCO_INVALID_SOCKET) {
				//DEBUGPOINT("SOCKET HAS BECOME INVALID\n");
				delete ss_ptr;
				continue;
			}
			void * ptr = lua_newuserdata(L, sizeof(Poco::Net::StreamSocket*));
			*(Poco::Net::StreamSocket**)ptr = ss_ptr;
			//DEBUGPOINT("[%p] got from pool\n", ss_ptr);
			luaL_setmetatable(L, _stream_socket_type_name);
		}
		else {
			lua_pushnil(L);
			break;
		}
	}

	return 1;
}

static std::map<std::string, char*> sg_initialized_pools;
static int create_pool(lua_State* L)
{
	const char *poolname = luaL_checkstring(L, 1);
	auto it = sg_initialized_pools.find(poolname);
	sock_queue_holder qhf;
	init_pool_type(poolname, &qhf);

	struct pool_s * pool_ptr = (struct pool_s *)lua_newuserdata(L, sizeof(struct pool_s));

	pool_ptr->poolname = strdup(poolname);
	pool_ptr->lock = create_spin_lock();

	luaL_getmetatable(L, SOCKET_POOL);
	lua_setmetatable(L, -2);

	return 1;
}

static int pool_gc(lua_State *L)
{
	/* always free the handle */
    struct pool_s * pool_ptr = (struct pool_s *)luaL_checkudata(L, 1, SOCKET_POOL);
	free((void*)(pool_ptr->poolname));
	destroy_spin_lock(pool_ptr->lock);

	return 0;
}

/*
 * __tostring
 */
static int pool_tostring(lua_State *L)
{
    char *str = *(char **)luaL_checkudata(L, 1, SOCKET_POOL);
	//DEBUGPOINT("Here str = [%p]\n", str);
    lua_pushfstring(L, "%s", str);
    return 1;
}

extern "C" int luaopen_libevpoolrepos(lua_State *L);
int luaopen_libevpoolrepos(lua_State *L)
{
	static const luaL_Reg lua_pool_methods[] = {
		{"__gc", pool_gc},
		{"__tostring", pool_tostring},
		{ "add_to_pool", interface_add_to_pool},
		{ "share_from_pool", share_from_pool},
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

