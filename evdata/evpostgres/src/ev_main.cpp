#include "Poco/evnet/evnet.h"
#include "Poco/evdata/evpostgres/ev_postgres.h"

extern "C" {
int ev_postgres_connection(lua_State *L);
int ev_postgres_statement(lua_State *L);
}

/* 
 * library entry point
 */
extern "C" int luaopen_evrdbms_postgres(lua_State *L);
int luaopen_evrdbms_postgres(lua_State *L)
{
    ev_postgres_statement(L); 
    return ev_postgres_connection(L);
}

