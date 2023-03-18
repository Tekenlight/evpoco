#include "Poco/evnet/evnet.h"
#include "Poco/evdata/evsqlite/ev_sqlite3.h"

#include "Poco/evnet/evnet_lua.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"

extern "C" {
int ev_sqlite3_connection(lua_State *L);
int ev_sqlite3_statement(lua_State *L);
}

static void v_hello_world(void* v)
{
	DEBUGPOINT("Here v = %p\n", v);
	return;
}

/* 
 * library entry point
 */
extern "C" int luaopen_evrdbms_sqlite3(lua_State *L);
int luaopen_evrdbms_sqlite3(lua_State *L)
{
	/*
	DEBUGPOINT("Here\n");
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	Poco::evnet::EVServer * server = reqHandler->getServerPtr();
	server->submitRequestForTaskExecutionNR(v_hello_world, 0);
	DEBUGPOINT("Here\n");
	*/

    ev_sqlite3_statement(L); 
    ev_sqlite3_connection(L);

	//usleep(10000);

    return 1;
}

extern "C" int luaopen_libevsqlite(lua_State *L);
int luaopen_libevsqlite(lua_State *L)
{
    return luaopen_evrdbms_sqlite3(L);
}

