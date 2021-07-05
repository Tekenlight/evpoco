#include <string.h>

#include <sys/cdefs.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include "Poco/Foundation.h"

void open_ffi(lua_State * L)
{
	int type = lua_getglobal(L, "ffi");
	poco_assert((type == LUA_TTABLE) || (type == LUA_TNIL));
	if (type == LUA_TNIL) {
		lua_pushstring(L, "require");
		lua_pushstring(L, "ffi");
		int ret = 0;
		ret = lua_pcall(L, 2 , 1, 0);
		poco_assert(ret == LUA_OK);
		lua_setglobal(L, "ffi");
	}
	return;
}
