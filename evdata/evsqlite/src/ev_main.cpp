#include "Poco/evnet/evnet.h"
#include "Poco/evdata/evsqlite/ev_sqlite3.h"

extern "C" {
int ev_sqlite3_connection(lua_State *L);
int ev_sqlite3_statement(lua_State *L);
}

/* 
 * library entry point
 */
extern "C" int luaopen_evrdbms_sqlite3(lua_State *L);
int luaopen_evrdbms_sqlite3(lua_State *L)
{
	//DEBUGPOINT("Here\n");
    ev_sqlite3_statement(L); 
    ev_sqlite3_connection(L);

    return 1;
}

