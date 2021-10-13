#ifndef EV_SQL_ACCESS_H_INCLUDED
#define EV_SQL_ACCESS_H_INCLUDED

#include <string>

#include <sys/cdefs.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#ifdef _WIN32
    #define LUA_EXPORT __declspec(dllexport)
#else
    #define LUA_EXPORT
#endif

#ifdef _MSC_VER  /* all MS compilers define this (version) */
     #define snprintf _snprintf
#endif

#if defined __linux__
#include <endian.h>
#define ntohll be64toh
#define htonll htobe64
#endif

/*
 *
 * Table construction helper functions
 *
 * LUA_PUSH_ATTRIB_* creates string indexed (hashmap)
 * LUA_PUSH_ARRAY_* creates integer indexed (array)
 *
 */

#define LUA_PUSH_ATTRIB_INT(n, v) \
    lua_pushstring(L, n); \
    lua_pushinteger(L, v); \
    lua_rawset(L, -3); 

#define LUA_PUSH_ATTRIB_FLOAT(n, v) \
    lua_pushstring(L, n); \
    lua_pushnumber(L, v); \
    lua_rawset(L, -3); 

#define LUA_PUSH_ATTRIB_STRING_BY_LENGTH(n, v, len) \
    lua_pushstring(L, n); \
    lua_pushlstring(L, v, len); \
    lua_rawset(L, -3); 

#define LUA_PUSH_ATTRIB_STRING(n, v) \
    lua_pushstring(L, n); \
    lua_pushstring(L, v); \
    lua_rawset(L, -3); 

#define LUA_PUSH_ATTRIB_BOOL(n, v) \
    lua_pushstring(L, n); \
    lua_pushboolean(L, v); \
    lua_rawset(L, -3); 

#define LUA_PUSH_ATTRIB_NIL(n) \
    lua_pushstring(L, n); \
    lua_pushnil(L); \
    lua_rawset(L, -3); 



#define LUA_PUSH_ARRAY_INT(n, v) \
    lua_pushinteger(L, v); \
    lua_rawseti(L, -2, n); \
    n++; 

#define LUA_PUSH_ARRAY_FLOAT(n, v) \
    lua_pushnumber(L, v); \
    lua_rawseti(L, -2, n); \
    n++; 

#define LUA_PUSH_ARRAY_STRING(n, v) \
    lua_pushstring(L, v); \
    lua_rawseti(L, -2, n); \
    n++;

#define LUA_PUSH_ARRAY_STRING_LEN(n, v, len) \
    lua_pushlstring(L, v, len); \
    lua_rawseti(L, -2, n); \
    n++;

#define EVLUA_TABLE_PUSH_ARRAY_STRING(t, n, v) { \
	struct _evnet_lua_table_value_t val; \
	val.type = EV_LUA_TSTRING; \
	val.value.string_value = strdup(v); \
	add_iv_tuple(t, n, val);\
    n++; \
}

#define LUA_PUSH_ARRAY_STRING_BY_LENGTH(n, v, len) \
    lua_pushlstring(L, v, len); \
    lua_rawseti(L, -2, n); \
    n++;

#define LUA_PUSH_ARRAY_BOOL(n, v) \
    lua_pushboolean(L, v); \
    lua_rawseti(L, -2, n); \
    n++;

#define LUA_PUSH_ARRAY_NIL(n) \
    lua_pushnil(L); \
    lua_rawseti(L, -2, n); \
    n++;

/*
 *
 * Describes SQL to Lua API type conversions
 *
 */

typedef enum lua_push_type {
    LUA_PUSH_NIL = 0,
    LUA_PUSH_INTEGER,
    LUA_PUSH_NUMBER,
    LUA_PUSH_STRING,
    LUA_PUSH_BOOLEAN,

    LUA_PUSH_MAX
} lua_push_type_t;

/*
 * used for placeholder translations
 * from '?' to the .\d{4}
 */
#define MAX_PLACEHOLDERS        9999 
#define MAX_PLACEHOLDER_SIZE    (1+4) /* .\d{4} */

/*
 *
 * Common error strings
 * defined here for consistency in driver implementations
 *
 */

#define	EV_SQL_ERR_CONNECTION_FAILED    "Failed to connect to database: %s"
#define EV_SQL_ERR_DB_UNAVAILABLE	    "Database not available"
#define EV_SQL_ERR_EXECUTE_INVALID	    "Execute called on a closed or invalid statement"
#define EV_SQL_ERR_EXECUTE_FAILED	    "Execute failed: %s"
#define EV_SQL_ERR_FETCH_INVALID	    "Fetch called on a closed or invalid statement"
#define EV_SQL_ERR_FETCH_FAILED	        "Fetch failed %s"
#define EV_SQL_ERR_PARAM_MISCOUNT	    "Statement expected %d parameters but received %d"
#define EV_SQL_ERR_BINDING_PARAMS	    "Error binding statement parameters: %s"
#define EV_SQL_ERR_BINDING_EXEC	        "Error executing statement parameters: %s"
#define EV_SQL_ERR_FETCH_NO_EXECUTE     "Fetch called before execute"
#define EV_SQL_ERR_BINDING_RESULTS	    "Error binding statement results: %s"
#define EV_SQL_ERR_UNKNOWN_PUSH	        "Unknown push type in result set"
#define EV_SQL_ERR_ALLOC_STATEMENT	    "Error allocating statement handle: %s"
#define EV_SQL_ERR_PREP_STATEMENT	    "Error preparing statement handle: %s"
#define EV_SQL_ERR_INVALID_PORT	        "Invalid port: %d"
#define EV_SQL_ERR_ALLOC_RESULT	        "Error allocating result set: %s"
#define EV_SQL_ERR_DESC_RESULT	        "Error describing result set: %s"
#define EV_SQL_ERR_BINDING_TYPE_ERR     "Unknown or unsupported type `%s'"
#define EV_SQL_ERR_INVALID_STATEMENT    "Invalid statement handle"
#define EV_SQL_ERR_NOT_IMPLEMENTED      "Method %s.%s is not implemented"
#define EV_SQL_ERR_QUOTING_STR          "Error quoting string: %s"
#define EV_SQL_ERR_STATEMENT_BROKEN     "Statement unavailable: database closed"
#define EV_SQL_ERR_ALLOC				"Error allocating : %s"
#define EV_SQL_ERR_PROC					"Error processing statment : %s"




#define POSTGRES_DB_TYPE_NAME "POSTGRESQL"
#define SQLITE_DB_TYPE_NAME "SQLITE"
#define MYSQL_DB_TYPE_NAME "MYSQL"

#define DB_TYPES_MAP "DBTYPES"
#define STATEMENTS_MAP "STATEMENTS"


#define EV_SQL_LUA_STACK_BASE_INDEX "EV_SQL_LUA_STACK_BASE_INDEX"

typedef enum {
	ev_lua_string = 1,
	ev_lua_date,
	ev_lua_datetime,
	ev_lua_time,
	ev_lua_byte,
	ev_lua_number,
	ev_lua_integer,
	ev_lua_decimal,
	ev_lua_binary,
	ev_lua_boolean,
	ev_lua_int8_t,
	ev_lua_uint8_t,
	ev_lua_int16_t,
	ev_lua_uint16_t,
	ev_lua_int32_t,
	ev_lua_uint32_t,
	ev_lua_int64_t,
	ev_lua_uint64_t,
	ev_lua_duration,
	ev_lua_float,
	ev_lua_nullptr,
} ev_lua_datatypes;

/* Interval related definitions */
typedef struct {
	int64_t usec;
	int32_t day;
	int32_t mon;
} interval_s_type, *interval_p_type;


struct lua_bind_variable_s {
	int    type;
	void*  val;
	size_t size;
	const char * name;
};
typedef struct lua_bind_variable_s lua_bind_var_s_type;
typedef struct lua_bind_variable_s* lua_bind_var_p_type;


__BEGIN_DECLS
/*
 * convert string to lower case
 */
const char *ev_sql_strlower(char *in);

/*
 * replace '?' placeholders with .\d+ placeholders
 * to be compatible with the native driver API
 */
char *ev_sql_replace_placeholders(lua_State *L, char native_prefix, const char *sql);

void ev_sql_register(lua_State *L, const char *name,
		  const luaL_Reg *methods, const luaL_Reg *class_methods,
		  lua_CFunction gc, lua_CFunction tostring);


int socket_live(int fd);

__END_DECLS

#endif
