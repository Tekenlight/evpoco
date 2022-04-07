#include "Poco/evdata/evmysql/ev_mysql.h"

extern "C" {
int ev_mysql_connection(lua_State *L);
int ev_mysql_statement(lua_State *L);
}

/*
 * library entry point
 */
extern "C" int luaopen_evrdbms_mysql(lua_State *L);
LUA_EXPORT int luaopen_evrdbms_mysql(lua_State *L) {
    ev_mysql_statement(L);
    ev_mysql_connection(L);

    return 1;
}
