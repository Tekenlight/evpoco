#include "Poco/evdata/evsqlite/ev_sqlite3.h"
#include "Poco/evnet/evnet_lua.h"

extern "C" {
int try_begin_transaction(connection_t *conn);
int try_end_transaction(connection_t *conn);
int completion_common_routine(lua_State* L, int status, lua_KContext ctx);
gen_lua_user_data_t* get_generic_lua_userdata(const char * name, void * data, size_t size);
}

/*
 * Converts SQLite types to Lua types
 */
static lua_push_type_t sqlite_to_lua_push(unsigned int sqlite_type)
{
    lua_push_type_t lua_type;

    switch(sqlite_type) {
		case SQLITE_NULL:
			lua_type = LUA_PUSH_NIL;
			break;

		case SQLITE_INTEGER:
			lua_type =  LUA_PUSH_INTEGER;
			break;

		case SQLITE_FLOAT:
			lua_type = LUA_PUSH_NUMBER;
			break;

		default:
			lua_type = LUA_PUSH_STRING;
    }

    return lua_type;
}

/*
 * runs sqlite3_step on a statement handle
 */
static int step(statement_t *statement)
{
	int res = sqlite3_step(statement->stmt);

	if (res == SQLITE_DONE) {
		statement->more_data = 0;
		return 1;
	} else if (res == SQLITE_ROW) {
		statement->more_data = 1;
		return 1;
	}

	return 0;
}

static void* vs_step(void* v)
{
	//DEBUGPOINT("vs_step() for %p\n", getL(iparams));
	statement_t* statement = (statement_t*)v;
	int res = sqlite3_step(statement->stmt);
	int * ip = (int*)malloc(sizeof(int));

	*ip = 0;
	if (res == SQLITE_DONE) {
		statement->more_data = 0;
		*ip = 1;
	} else if (res == SQLITE_ROW) {
		statement->more_data = 1;
		*ip = 1;
	}

	//DEBUGPOINT("Here *ip = %d\n", *ip);

	return ip;
}

static int int_step_completion(lua_State* L, int status, lua_KContext ctx)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	//DEBUGPOINT("int_step_completion() for %d\n", reqHandler->getAccSockfd());
	Poco::evnet::EVUpstreamEventNotification &usN = reqHandler->getUNotification();
	statement_t* statement = 0;
	statement = (statement_t*)ctx;

	if (usN.getRet() != 0) {
		char * msg = (char*)"Error occured during invocation";
		luaL_error(L, msg);
		return 0;
	}

	int * ip = (int*)(usN.getTaskReturnValue());
	usN.setTaskReturnValue(NULL);
    if (*ip == 0) {
		if (sqlite3_reset(statement->stmt) != SQLITE_OK) {
			/* 
			 * reset needs to be called to retrieve the 'real' error message
			 */
			free(ip);
			return luaL_error(L, EV_SQL_ERR_FETCH_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		}
    }

	//DEBUGPOINT("Here *ip = %d\n", *ip);
	free(ip);

	return 1;
}

/*
 * num_affected_rows = statement:affected()
 */
static int statement_affected(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);

    if (!statement->stmt) {
        luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
    }

    lua_pushinteger(L, statement->affected);
 
    return 1;   
}

/*
 * success = statement:close()
 */
static int statement_close(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
    int ok = 0;

    if (statement->stmt) {
	if (sqlite3_finalize(statement->stmt) == SQLITE_OK) {
	    ok = 1;
	}

	statement->stmt = NULL;
    }

    lua_pushboolean(L, ok);
    return 1;
}

static void vs_nr_func(void* i)
{
	return;
}

/*
 * cleanup function in use
 */
static void vs_nr_statement_close(void* v)
{
    statement_t *statement = (statement_t *)v;
	sqlite3_finalize(statement->stmt);
	statement->stmt = NULL;
	free(statement);
	statement = NULL;
	return ;
}

static void * vs_statement_close(void* v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
	//DEBUGPOINT("vs_statement_close() for %p\n", getL(iparams));
    statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams,1);
	//DEBUGPOINT("Here udata of statement = %p\n", statement);
    int ok = 0;

	if (sqlite3_finalize(statement->stmt) == SQLITE_OK) {
	    ok = 1;
	}
	statement->stmt = NULL;

	generic_task_params_ptr_t oparams = new_generic_task_params();
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &ok);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_statement_close(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
    int ok = 0;

	if (!(statement->stmt)) {
		lua_pushboolean(L, ok);
		return 1;
	}

	//DEBUGPOINT("Here udata of statement = %p\n", statement);
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_statement_close, params);
	return lua_yieldk(L, 0, (lua_KContext)"statement could not be closed", completion_common_routine);
}


/*
 * column_names = statement:columns()
 */
static int statement_columns(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	//DEBUGPOINT("statement_columns() for %d\n", reqHandler->getAccSockfd());

    int i;
    int num_columns;
    int d = 1;

    if (!statement->stmt) {
        luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
        return 0;
    }

    num_columns = sqlite3_column_count(statement->stmt);
    lua_newtable(L);
    for (i = 0; i < num_columns; i++) {
        const char *name = sqlite3_column_name(statement->stmt, i);

        LUA_PUSH_ARRAY_STRING(d, name);
    }

    return 1;
}

static void* vs_statement_columns(void* v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams,1);

    int i;
    int num_columns;
    int d = 1;

    num_columns = sqlite3_column_count(statement->stmt);

	evnet_lua_table_t * table = new evnet_lua_table_t();
    //lua_newtable(L);
    for (i = 0; i < num_columns; i++) {
        const char *name = sqlite3_column_name(statement->stmt, i);

		EVLUA_TABLE_PUSH_ARRAY_STRING(table, d, name);
        //LUA_PUSH_ARRAY_STRING(d, name);
    }

	generic_task_params_ptr_t oparams = new_generic_task_params();
	set_lua_stack_out_param(oparams, EV_LUA_TTABLE, table);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_statement_columns(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);

    int i;
    int num_columns;
    int d = 1;

    if (!statement->stmt) {
        luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
        return 0;
    }

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_statement_columns, params);
	return lua_yieldk(L, 0, (lua_KContext)"statement columns could not be fetched", completion_common_routine);
}

/*
 * success,err = statement:execute(...)
 */
static int statement_execute(lua_State *L)
{
	int n = lua_gettop(L);
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
	int p;
	int errflag = 0;
	const char *errstr = NULL;
	int expected_params;
	int num_bind_params = n - 1;

	if (!statement->stmt) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, EV_SQL_ERR_EXECUTE_INVALID);
		return 2;
	}

	/*
	 * sanity check: make sure our database handle is still open
	 */
	if (!statement->conn->sqlite) {
		lua_pushstring(L, EV_SQL_ERR_STATEMENT_BROKEN);
		lua_error(L);
	}


	/*
	 * reset the handle before binding params
	 * this will be a NOP if the handle has not
	 * been executed
	 */
	if (sqlite3_reset(statement->stmt) != SQLITE_OK) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_EXECUTE_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		return 2;
	}

	sqlite3_clear_bindings(statement->stmt);

	expected_params = sqlite3_bind_parameter_count(statement->stmt);
	if (expected_params != num_bind_params) {
		/*
			 * sqlite3_reset does not handle this condition,
			 * and the client library will fill unset params
			 * with NULLs
			 */ 
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_PARAM_MISCOUNT, expected_params, num_bind_params); 
		return 2;
	}

	for (p = 2; p <= n; p++) {
		int i = p - 1;
		int type = lua_type(L, p);
		char err[64];

		switch(type) {
		case LUA_TNIL:
			errflag = sqlite3_bind_null(statement->stmt, i) != SQLITE_OK;
			break;
		case LUA_TNUMBER:
			errflag = sqlite3_bind_double(statement->stmt, i, lua_tonumber(L, p)) != SQLITE_OK;
			break;
		case LUA_TSTRING: {
			size_t len = -1;
			const char *str = lua_tolstring(L, p, &len);
			errflag = sqlite3_bind_text(statement->stmt, i, str, len, SQLITE_STATIC) != SQLITE_OK;
			break;
		}
		case LUA_TBOOLEAN:
			errflag = sqlite3_bind_int(statement->stmt, i, lua_toboolean(L, p)) != SQLITE_OK;
			break;
		default:
			/*
			 * Unknown/unsupported value type
			 */
			errflag = 1;
			snprintf(err, sizeof(err)-1, EV_SQL_ERR_BINDING_TYPE_ERR, lua_typename(L, type));
			errstr = err;
		}

		if (errflag)
			break;
	}   

	if (errflag) {
		lua_pushboolean(L, 0);
		if (errstr)
			lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, errstr);
		else
			lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, sqlite3_errmsg(statement->conn->sqlite));

		return 2;
	}

	try_begin_transaction(statement->conn);

	if (!step(statement)) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_EXECUTE_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		return 2;
	}

	statement->affected = sqlite3_changes(statement->conn->sqlite);

	lua_pushboolean(L, 1);
	return 1;
}

static void* vs_statement_execute(void* v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
    statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams,1);

	iparams = destroy_generic_task_in_params(iparams);
	try_begin_transaction(statement->conn);

	int ok = 0;
	generic_task_params_ptr_t oparams = new_generic_task_params();
	if (!step(statement)) {
		set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &ok);
		char str[1024];
		sprintf(str, EV_SQL_ERR_EXECUTE_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return oparams;
	}
	ok = 1;

	statement->affected = sqlite3_changes(statement->conn->sqlite);
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &ok);

	//DEBUGPOINT("Here\n");
	return oparams;
}

static int initiate_statement_execute(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	//DEBUGPOINT("initiate_statement_execute() for %d\n", reqHandler->getAccSockfd());
	int n = lua_gettop(L);
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
	int p;
	int errflag = 0;
	const char *errstr = NULL;
	int expected_params;
	int num_bind_params = n - 1;

	if (!statement->stmt) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, EV_SQL_ERR_EXECUTE_INVALID);
		return 2;
	}

	/*
	 * sanity check: make sure our database handle is still open
	 */
	if (!statement->conn->sqlite) {
		lua_pushstring(L, EV_SQL_ERR_STATEMENT_BROKEN);
		lua_error(L);
	}


	/*
	 * reset the handle before binding params
	 * this will be a NOP if the handle has not
	 * been executed
	 *
	 * We are assuming that sqlite3_reset does not make
	 * any disk operations.
	 */
	if (sqlite3_reset(statement->stmt) != SQLITE_OK) {
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_EXECUTE_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		return 2;
	}

	/*
	 * We are making assumption that sqlite3_clear_bindings
	 * wont make any disk operations
	 * */
	sqlite3_clear_bindings(statement->stmt);

	/* Likewise for sqlite3_bind_parameter_count */
	expected_params = sqlite3_bind_parameter_count(statement->stmt);
	if (expected_params != num_bind_params) {
		/*
			 * sqlite3_reset does not handle this condition,
			 * and the client library will fill unset params
			 * with NULLs
			 */ 
		lua_pushboolean(L, 0);
		lua_pushfstring(L, EV_SQL_ERR_PARAM_MISCOUNT, expected_params, num_bind_params); 
		return 2;
	}

	for (p = 2; p <= n; p++) {
		int i = p - 1;
		int type = lua_type(L, p);
		char err[64];

		switch(type) {
			case LUA_TNIL:
				errflag = sqlite3_bind_null(statement->stmt, i) != SQLITE_OK;
				break;
			case LUA_TNUMBER:
				errflag = sqlite3_bind_double(statement->stmt, i, lua_tonumber(L, p)) != SQLITE_OK;
				break;
			case LUA_TSTRING: {
				size_t len = -1;
				const char *str = lua_tolstring(L, p, &len);
				errflag = sqlite3_bind_text(statement->stmt, i, str, len, SQLITE_STATIC) != SQLITE_OK;
				break;
			}
			case LUA_TBOOLEAN:
				errflag = sqlite3_bind_int(statement->stmt, i, lua_toboolean(L, p)) != SQLITE_OK;
				break;
			default:
				/*
				 * Unknown/unsupported value type
				 */
				errflag = 1;
				snprintf(err, sizeof(err)-1, EV_SQL_ERR_BINDING_TYPE_ERR, lua_typename(L, type));
				errstr = err;
		}

		if (errflag)
			break;
	}   

	if (errflag) {
		lua_pushboolean(L, 0);
		if (errstr)
			lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, errstr);
		else
			lua_pushfstring(L, EV_SQL_ERR_BINDING_PARAMS, sqlite3_errmsg(statement->conn->sqlite));
		
		return 2;
	}

	//DEBUGPOINT("Here\n");
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	poco_assert(reqHandler != NULL);
	//DEBUGPOINT("Here for %d\n", reqHandler->getAccSockfd());
	reqHandler->executeGenericTask(NULL, &vs_statement_execute, params);
	return lua_yieldk(L, 0, (lua_KContext)"statement could not be executed", completion_common_routine);
}

/*
 * must be called after an execute
 */
static int statement_fetch_impl(lua_State *L, statement_t *statement, int named_columns)
{
    int num_columns;

    if (!statement->stmt) {
	luaL_error(L, EV_SQL_ERR_FETCH_INVALID);
	return 0;
    }

    if (!statement->more_data) {
	/* 
         * Result set is empty, or not result set returned
         */
  
	lua_pushnil(L);
	return 1;
    }

    num_columns = sqlite3_column_count(statement->stmt);

    if (num_columns) {
		int i;
		int d = 1;

		lua_newtable(L);

		for (i = 0; i < num_columns; i++) {
			lua_push_type_t lua_push = sqlite_to_lua_push(sqlite3_column_type(statement->stmt, i));
			const char *name = sqlite3_column_name(statement->stmt, i);

			if (lua_push == LUA_PUSH_NIL) {
				if (named_columns) {
					LUA_PUSH_ATTRIB_NIL(name);
				} else {
					LUA_PUSH_ARRAY_NIL(d);
				}
			} else if (lua_push == LUA_PUSH_INTEGER) {
				int val = sqlite3_column_int(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_INT(name, val);
				} else {
					LUA_PUSH_ARRAY_INT(d, val);
				}
			} else if (lua_push == LUA_PUSH_NUMBER) {
				double val = sqlite3_column_double(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_FLOAT(name, val);
				} else {
					LUA_PUSH_ARRAY_FLOAT(d, val);
				}
			} else if (lua_push == LUA_PUSH_STRING) {
				const char *val = (const char *)sqlite3_column_text(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_STRING(name, val);
				} else {
					LUA_PUSH_ARRAY_STRING(d, val);
				}
			} else if (lua_push == LUA_PUSH_BOOLEAN) {
				int val = sqlite3_column_int(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_BOOL(name, val);
				} else {
					LUA_PUSH_ARRAY_BOOL(d, val);
				}
			} else {
				luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
			}
		}
    } else {
		/* 
		 * no columns returned by statement?
		 */ 
		lua_pushnil(L);
    }

    if (step(statement) == 0) {
		if (sqlite3_reset(statement->stmt) != SQLITE_OK) {
			/* 
			 * reset needs to be called to retrieve the 'real' error message
			 */
			luaL_error(L, EV_SQL_ERR_FETCH_FAILED, sqlite3_errmsg(statement->conn->sqlite));
		}
    }

    return 1;    
}

static int initiate_statement_fetch_impl(lua_State *L, statement_t *statement, int named_columns)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	//DEBUGPOINT("initiate_statement_fetch_impl() for %d\n", reqHandler->getAccSockfd());
    int num_columns;

    if (!statement->stmt) {
		luaL_error(L, EV_SQL_ERR_FETCH_INVALID);
		return 0;
    }

    if (!statement->more_data) {
		/* 
		 * Result set is empty, or not result set returned
		 */
	  
		lua_pushnil(L);
		return 1;
    }

    num_columns = sqlite3_column_count(statement->stmt);
    if (num_columns) {
		int i;
		int d = 1;

		lua_newtable(L);

		for (i = 0; i < num_columns; i++) {
			lua_push_type_t lua_push = sqlite_to_lua_push(sqlite3_column_type(statement->stmt, i));
			const char *name = sqlite3_column_name(statement->stmt, i);

			if (lua_push == LUA_PUSH_NIL) {
				if (named_columns) {
					LUA_PUSH_ATTRIB_NIL(name);
				}
				else {
					LUA_PUSH_ARRAY_NIL(d);
				}
			}
			else if (lua_push == LUA_PUSH_INTEGER) {
				int val = sqlite3_column_int(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_INT(name, val);
				}
				else {
					LUA_PUSH_ARRAY_INT(d, val);
				}
			}
			else if (lua_push == LUA_PUSH_NUMBER) {
				double val = sqlite3_column_double(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_FLOAT(name, val);
				}
				else {
					LUA_PUSH_ARRAY_FLOAT(d, val);
				}
			}
			else if (lua_push == LUA_PUSH_STRING) {
				const char *val = (const char *)sqlite3_column_text(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_STRING(name, val);
				}
				else {
					LUA_PUSH_ARRAY_STRING(d, val);
				}
			}
			else if (lua_push == LUA_PUSH_BOOLEAN) {
				int val = sqlite3_column_int(statement->stmt, i);

				if (named_columns) {
					LUA_PUSH_ATTRIB_BOOL(name, val);
				}
				else {
					LUA_PUSH_ARRAY_BOOL(d, val);
				}
			}
			else {
				luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
			}
		}
    }
	else {
		/* 
		 * no columns returned by statement?
		 */ 
		lua_pushnil(L);
    }


	reqHandler->executeGenericTask(NULL, &vs_step, statement);
	return lua_yieldk(L, 0, (lua_KContext)statement, int_step_completion);
}

static int next_iterator(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, lua_upvalueindex(1), EV_SQLITE_STATEMENT);
    int named_columns = lua_toboolean(L, lua_upvalueindex(2));

    //return statement_fetch_impl(L, statement, named_columns);
    return initiate_statement_fetch_impl(L, statement, named_columns);
}

/*
 * table = statement:fetch(named_indexes)
 */
static int statement_fetch(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
    int named_columns = lua_toboolean(L, 2);

    //return statement_fetch_impl(L, statement, named_columns);
    return initiate_statement_fetch_impl(L, statement, named_columns);
}

/*
 * iterfunc = statement:rows(named_indexes)
 */
static int statement_rows(lua_State *L)
{
    if (lua_gettop(L) == 1) {
        lua_pushvalue(L, 1);
        lua_pushboolean(L, 0);
    } else {
        lua_pushvalue(L, 1);
        lua_pushboolean(L, lua_toboolean(L, 2));
    }

    lua_pushcclosure(L, next_iterator, 2);
    return 1;
}

/*
 * num_rows = statement:rowcount()
 */
static int statement_rowcount(lua_State *L)
{
    luaL_error(L, EV_SQL_ERR_NOT_IMPLEMENTED, EV_SQLITE_STATEMENT, "rowcount");
    return 0;
}

/*
 * __gc
 */
static int statement_gc(lua_State *L)
{
    statement_close(L);

    return 0;
}

static int new_statement_gc(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

    statement_t *l_statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);
    int ok = 0;
	if (!(l_statement->stmt)) {
		lua_pushboolean(L, ok);
		return 1;
	}

    statement_t *statement = NULL;
    statement = (statement_t *)malloc(sizeof(statement_t));
	memcpy(statement, l_statement, sizeof(statement_t));

	vs_nr_statement_close(statement);

    return 0;
}

/*
 * __tostring
 */
static int statement_tostring(lua_State *L)
{
    statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_SQLITE_STATEMENT);

    lua_pushfstring(L, "%s: %p", EV_SQLITE_STATEMENT, statement);

    return 1;
}

/* original function */
extern "C" int db_sqlite3_statement_create(lua_State *L, connection_t *conn, const char *sql_query);
int db_sqlite3_statement_create(lua_State *L, connection_t *conn, const char *sql_query)
{ 
    statement_t *statement = NULL;

    statement = (statement_t *)lua_newuserdata(L, sizeof(statement_t));
    statement->conn = conn;
    statement->stmt = NULL;
    statement->more_data = 0;
    statement->affected = 0;

    if (sqlite3_prepare_v2(statement->conn->sqlite, sql_query, strlen(sql_query), &statement->stmt, NULL) != SQLITE_OK) {
	lua_pushnil(L);
	lua_pushfstring(L, EV_SQL_ERR_PREP_STATEMENT, sqlite3_errmsg(statement->conn->sqlite));	
	return 2;
    } 

    luaL_getmetatable(L, EV_SQLITE_STATEMENT);
    lua_setmetatable(L, -2);
    return 1;
} 

extern "C" void ev_sqlite3_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams,
																connection_t *conn, const char *sql_query);

void ev_sqlite3_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams,
																connection_t *conn, const char *sql_query)
{ 
	//DEBUGPOINT("ev_sqlite3_statement_create() for %p\n", getL(iparams));
    statement_t *statement = NULL;

    statement = (statement_t *)malloc(sizeof(statement_t));
    statement->conn = conn;
    statement->stmt = NULL;
    statement->more_data = 0;
    statement->affected = 0;

    if (sqlite3_prepare_v2(statement->conn->sqlite, sql_query, strlen(sql_query), &statement->stmt, NULL) != SQLITE_OK) {
		set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
		char str[1024];
		sprintf(str, EV_SQL_ERR_PREP_STATEMENT, sqlite3_errmsg(statement->conn->sqlite));	
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		free(statement);
		return ;
    } 

	set_lua_stack_out_param(oparams, EV_LUA_TUSERDATA,
				get_generic_lua_userdata(EV_SQLITE_STATEMENT, statement, sizeof(statement_t)));

    return ;
} 

extern "C" int ev_sqlite3_statement(lua_State *L);
int ev_sqlite3_statement(lua_State *L)
{
    static const luaL_Reg statement_methods[] = {
	{"affected", statement_affected}, // Not required, only memory operation.
	{"close", initiate_statement_close}, // Done
	//{"close", statement_close}, // Done
	{"columns", statement_columns}, // Not required to do this for sqlite
	{"execute", initiate_statement_execute}, // Done. The program terminated with SEGV once
	//{"execute", statement_execute}, // Done. The program terminated with SEGV once
	{"fetch", statement_fetch}, // Done through initiate_statement_fetch_impl
	{"rows", statement_rows}, // Done through closure of next_iterator and then initiate_statement_fetch_impl
	{"rowcount", statement_rowcount}, // Not required
	{NULL, NULL}
    };

    static const luaL_Reg statement_class_methods[] = {
	{NULL, NULL}
    };

    ev_sql_register(L, EV_SQLITE_STATEMENT,
		 statement_methods, statement_class_methods,
		 new_statement_gc, statement_tostring);

    return 1;    
}

