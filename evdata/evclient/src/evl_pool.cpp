extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}
#include "Poco/evnet/EVLHTTPRequestHandler.h"

extern void add_conn_to_pool(const char * type, const char * host, const char * name, void * conn);
extern void * get_conn_from_pool(const char * type, const char * host, const char * name);

const static char *_stream_socket_type_name = "streamsocket";

#define CLIENT_OBJECT_POOL "socket_connection_pool"

void init_pool_type(const char * db_type, Poco::evnet::evl_pool::queue_holder *qhf);

class queue_holder : public Poco::evnet::evl_pool::queue_holder {
	public:
	virtual Poco::evnet::evl_pool::queue_holder* clone()
	{
		return (Poco::evnet::evl_pool::queue_holder*)(new queue_holder());
	}
	virtual ~queue_holder() {
		Poco::Net::StreamSocket * conn = (Poco::Net::StreamSocket*)dequeue(_queue);
		while (conn) {
			delete conn;
		}
		wf_destroy_ev_queue(_queue);
	}
};

static int add_to_pool(lua_State* L)
{
	const char *type = luaL_checkstring(L, 1);
	const char *host = luaL_checkstring(L, 2);
	const char *name = luaL_checkstring(L, 3);
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 4, _stream_socket_type_name);
	add_conn_to_pool(type, host, name, ss_ptr);
	return 0;
}

static int get_from_pool(lua_State* L)
{
	const char *type = luaL_checkstring(L, 1);
	const char *host = luaL_checkstring(L, 2);
	const char *name = luaL_checkstring(L, 3);
	Poco::Net::StreamSocket * ss_ptr =  (Poco::Net::StreamSocket*)get_conn_from_pool(type, host, name);

	if (NULL != ss_ptr)
		lua_pushlightuserdata(L, ss_ptr);
	else
		lua_pushnil(L);

	return 1;
}


extern "C" int luaopen_libevclient(lua_State *L);
int luaopen_libevclient(lua_State *L)
{
	queue_holder qhf;
	static int initialized = 0;
	static const luaL_Reg lua_evclient_methods[] = {
		{ "add_to_pool", add_to_pool}
		,{ "get_from_pool", get_from_pool}
		,{NULL, NULL}
	};

	luaL_newlib(L, lua_evclient_methods);

	if (!initialized) {
		init_pool_type(CLIENT_OBJECT_POOL, &qhf);
	}
	initialized = 1;

	return 1;    
}

