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
#include <Poco/evdata/luaffi_capi.h>

extern "C" {
int raw_set_ffi_capi(lua_State *L);
const luaffi_capi_v1 * get_ffi_api();
}

static const luaffi_capi_v1 *ffi_api = NULL;

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

int raw_set_ffi_capi(lua_State *L)
{
    const luaffi_capi_v1 *api;

    //fprintf(stderr, "raw_set_ffi_capi: ENTER L=%p\n", (void *)L);

    if (!lua_islightuserdata(L, 1)) {
        //fprintf(stderr, "raw_set_ffi_capi: argument type=%s\n", luaL_typename(L, 1));
        return luaL_error(L, "luaffi C API pointer expected");
    }

    api = (const luaffi_capi_v1 *) lua_touserdata(L, 1);

    //fprintf(stderr, "raw_set_ffi_capi: api=%p\n", (void *)api);

    if (api == NULL) {
        return luaL_error(L, "NULL luaffi C API");
    }

    //fprintf(stderr, "raw_set_ffi_capi: version=%u size=%u\n", api->version, api->size);

    /*
    fprintf(stderr, "raw_set_ffi_capi: push_int16=%p push_int32=%p push_int64=%p push_float=%p push_null=%p\n",
            (void *)api->push_int16,
            (void *)api->push_int32,
            (void *)api->push_int64,
            (void *)api->push_float,
            (void *)api->push_null
        );
    */

    if (api->version != LUAFFI_CAPI_VERSION) {
        return luaL_error(L, "incompatible luaffi C API version: %u", api->version);
    }

    if (api->size < sizeof(luaffi_capi_v1)) {
        return luaL_error(L, "luaffi C API structure too small");
    }

    if (api->push_int16 == NULL ||
        api->push_int32 == NULL ||
        api->push_int64 == NULL ||
        api->push_float == NULL ||
        api->push_null == NULL) {
        return luaL_error(L, "incomplete luaffi C API");
    }

    ffi_api = api;

    //fprintf(stderr, "raw_set_ffi_capi: ffi_api SET TO %p\n", (void *)ffi_api);


    lua_pushboolean(L, 1);

    return 1;
}

const luaffi_capi_v1 * get_ffi_api()
{
    return ffi_api;
}

