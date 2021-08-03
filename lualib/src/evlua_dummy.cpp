extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

void dumm(lua_State *L)
{
	lua_pushstring(L, "");
}
