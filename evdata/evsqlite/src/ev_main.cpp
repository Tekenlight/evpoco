#include "Poco/evdata/evsqlite/ev_sqlite3.h"

namespace evpoco {
namespace evdata {
namespace evsqlite {

int ev_sqlite3_connection(lua_State *L);
int ev_sqlite3_statement(lua_State *L);

/* 
 * library entry point
 */
LUA_EXPORT int luaopen_evrdbms_sqlite3(lua_State *L) {
    ev_sqlite3_statement(L); 
    ev_sqlite3_connection(L);

    return 1;
}

}
}
}
