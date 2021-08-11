extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}


#include "Poco/Crypto/DigestEngine.h"

static int generate_hash_from_string(lua_State *L)
{
	const char * inp_str = lua_tostring(L, 1);
	if (inp_str == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "s_hash(s, salt): Input string manadatory");
		return 2;

	}
	const char * salt = luaL_tolstring(L, 2, NULL);
	size_t len = strlen(inp_str) + ((salt)?strlen(salt):0);
	char * str = (char*)malloc(len+1);
	strcpy(str, inp_str);
	if (salt) strcat(str, salt);

	Poco::Crypto::DigestEngine d("SHA256");
	d.update((const void *)str, len);

	std::string digest = d.digestToHex(d.digest());


	lua_pushstring(L, digest.c_str());

	free(str);
	return 1;
}

extern "C" int luaopen_libevlcrypto(lua_State *L);
int luaopen_libevlcrypto(lua_State *L)
{
	static const luaL_Reg lua_crypto_methods[] = {
		{"s_hash", generate_hash_from_string}
		,{NULL, NULL}
	};

	luaL_newlib(L, lua_crypto_methods);


	return 1;    
}

