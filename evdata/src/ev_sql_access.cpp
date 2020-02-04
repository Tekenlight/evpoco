#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sqlite3.h>

#include <Poco/evdata/ev_sql_access.h>
#include <Poco/evnet/evnet_lua.h>

#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#include "Poco/evnet/evnet_lua.h"

extern "C" {
int completion_common_routine(lua_State* L, int status, lua_KContext ctx);
}

const char *ev_sql_strlower(char *in) {
    char *s = in;

    while(*s) {
	*s= (*s <= 'Z' && *s >= 'A') ? (*s - 'A') + 'a' : *s;
	s++;
    }

    return in;
}

/*
 * replace '?' placeholders with {native_prefix}\d+ placeholders
 * to be compatible with native API
 */
char *ev_sql_replace_placeholders(lua_State *L, char native_prefix, const char *sql) {
    size_t len = strlen(sql);
    int num_placeholders = 0;
    int extra_space = 0;
    size_t i;
    char *newsql;
    int newpos = 1;
    int ph_num = 1;
    int in_quote = 0;
    char format_str[4];

    format_str[0] = native_prefix;
    format_str[1] = '%';
    format_str[2] = 'u';
    format_str[3] = '\0';

    /*
     * dumb count of all '?'
     * this will match more placeholders than necessesary
     * but it's safer to allocate more placeholders at the
     * cost of a few bytes than risk a buffer overflow
     */ 
    for (i = 1; i < len; i++) {
	if (sql[i] == '?') {
	    num_placeholders++;
	}
    }
    
    /*
     * this is MAX_PLACEHOLDER_SIZE-1 because the '?' is 
     * replaced with '{native_prefix}'
     */ 
    extra_space = num_placeholders * (MAX_PLACEHOLDER_SIZE-1); 

    /*
     * allocate a new string for the converted SQL statement
     */
    newsql = (char*)calloc(len+extra_space+1, sizeof(char));
    if(!newsql) {
    	lua_pushliteral(L, "out of memory");
	/* lua_error does not return. */
    	lua_error(L);
    }

    /* 
     * copy first char. In valid SQL this cannot be a placeholder
     */
    newsql[0] = sql[0];

    /* 
     * only replace '?' not in a single quoted string
     */
    for (i = 1; i < len; i++) {
	/*
	 * don't change the quote flag if the ''' is preceded 
	 * by a '\' to account for escaping
	 */
	if (sql[i] == '\'' && sql[i-1] != '\\') {
	    in_quote = !in_quote;
	}

	if (sql[i] == '?' && !in_quote) {
	    size_t n;

	    if (ph_num > MAX_PLACEHOLDERS) {
		luaL_error(L, "Sorry, you are using more than %d placeholders. Use %c{num} format instead", MAX_PLACEHOLDERS, native_prefix);
	    }

	    n = snprintf(&newsql[newpos], MAX_PLACEHOLDER_SIZE, format_str, ph_num++);

	    newpos += n;
	} else {
	    newsql[newpos] = sql[i];
	    newpos++;
	}
    }

    /* 
     * terminate string on the last position 
     */
    newsql[newpos] = '\0';

    /* fprintf(stderr, "[%s]\n", newsql); */
    return newsql;
}

void ev_sql_register(lua_State *L, const char *name,
		  const luaL_Reg *methods, const luaL_Reg *class_methods,
		  lua_CFunction gc, lua_CFunction tostring)
{
    /* Create a new metatable with the given name and then assign the methods
     * to it.  Set the __index, __gc and __tostring fields appropriately.
     */
    luaL_newmetatable(L, name);
    luaL_setfuncs(L, methods, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");

    lua_pushcfunction(L, tostring);
    lua_setfield(L, -2, "__tostring");

    /* Create a new table and register the class methods with it */
    lua_newtable(L);
    luaL_setfuncs(L, class_methods, 0);
}

int completion_common_routine(lua_State* L, int status, lua_KContext ctx)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	if (usN.getRet() != 0) {
		char * msg = (char*)ctx;
		if (!msg) msg = (char*)"Error occured during invocation";
		luaL_error(L, msg);
		return 0;
	}
	generic_task_params_ptr_t oparams = (generic_task_params_ptr_t)(usN.getTaskReturnValue());
	usN.setTaskReturnValue(NULL);
	push_out_params_to_lua_stack(oparams, L);
	int n = get_num_generic_params(oparams);

	//DEBUGPOINT("Here\n");
	oparams = destroy_generic_task_out_params(oparams);
	//DEBUGPOINT("Here\n");
	return n;
}

