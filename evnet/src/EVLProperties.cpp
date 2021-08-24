extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include "Poco/Util/Application.h"

static Poco::Util::AbstractConfiguration& appConfig()
{
	try {
		return Poco::Util::Application::instance().config();
	}
	catch (...) {
		throw Poco::IllegalStateException(
			"An application configuration is required "
			"but no Poco::Util::Application instance is available."
		);
	}
}


static int get_string_property(lua_State *L)
{
	const char * name = luaL_checkstring(L, 1);
	std::string prop_value;
	bool exception = false;
	try {
		Poco::Util::AbstractConfiguration& config = appConfig();
		prop_value = config.getString(std::string(name));
	}
	catch (...) {
		exception = true;
	}

	if (exception) {
		lua_pushnil(L);
	}
	else {
		lua_pushstring(L, prop_value.c_str());
	}
	return 1;
}


static int get_int_property(lua_State *L)
{
	const char * name = luaL_checkstring(L, 1);
	int prop_value = 0;
	bool exception = false;
	try {
		Poco::Util::AbstractConfiguration& config = appConfig();
		prop_value = config.getInt(std::string(name));
	}
	catch (...) {
		exception = true;
	}

	if (exception) {
		lua_pushnil(L);
	}
	else {
		lua_pushinteger(L, prop_value);
	}
	return 1;
}

static int get_bool_property(lua_State *L)
{
	const char * name = luaL_checkstring(L, 1);
	bool prop_value = false;
	bool exception = false;
	try {
		Poco::Util::AbstractConfiguration& config = appConfig();
		prop_value = config.getBool(std::string(name));
	}
	catch (...) {
		exception = true;
	}

	if (exception) {
		lua_pushnil(L);
	}
	else {
		lua_pushboolean(L, prop_value);
	}
	return 1;
}

int get_properties_funcs(lua_State *L)
{
	static const luaL_Reg properties_funcs[] = {
		{"get_bool_property", get_bool_property}
		,{"get_int_property", get_int_property}
		,{"get_string_property", get_string_property}
		,{NULL, NULL}
	};

	lua_newtable(L);
	luaL_setfuncs(L, properties_funcs, 0);

	return 1;
}


